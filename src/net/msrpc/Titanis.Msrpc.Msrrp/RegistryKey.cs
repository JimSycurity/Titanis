using System.Buffers.Binary;
using System.ComponentModel;
using System.Numerics;
using System.Text;
using System.Threading;
using Titanis.DceRpc;
using Titanis.Winterop;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Titanis.Msrpc.Msrrp
{

	public partial class RegistryKey
	{
		// Exposed so TBO can read registry key security descriptors over MS-RRP.
		private const int DefaultSecurityDescriptorBufferSize = 8192;

		internal RegistryKey(string name, string path, RpcContextHandle hkey, RemoteRegistryClient owner)
		{
			this._hkey = hkey;
			this._owner = owner;

			this.KeyName = name;
			this.KeyPath = path;
		}

		private readonly RpcContextHandle _hkey;
		private readonly RemoteRegistryClient _owner;

		public string KeyName { get; }
		public string KeyPath { get; }


		public async Task<RegistryKey> CreateSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
		{
			RpcPointer<RpcContextHandle> phkResult = new();
			Win32ErrorCode res = (Win32ErrorCode)await this._owner.proxy.BaseRegCreateKey(this._hkey, (subkeyPath + '\0').ToRpcUnicodeString(), default, (uint)options, (uint)access, null, phkResult, new RpcPointer<uint>(), cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();

			return new RegistryKey(RegistryPath.GetSubkeyNameFromPath(subkeyPath), RegistryPath.Combine(this.KeyPath, subkeyPath), phkResult.value, this._owner);
		}

		public Task SetValue(string? valueName, string str, CancellationToken cancellationToken) => this.SetValue(valueName, RegistryValueType.String, Encoding.Unicode.GetBytes(str + '\0'), cancellationToken);

		public async Task SetValue(string? valueName, RegistryValueType valueKind, byte[] data, CancellationToken cancellationToken)
		{
			var res = (Win32ErrorCode)await _owner.proxy.BaseRegSetValue(
				_hkey,
				(valueName + "\0").ToRpcUnicodeString(),
				(uint)valueKind,
				data,
				(uint)data.Length,
				cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();
		}


		async Task<IRegistryKey> IRegistryKey.OpenSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken) => await OpenSubkey(subkeyPath, access, options, cancellationToken).ConfigureAwait(false);
		public async Task<RegistryKey> OpenSubkey(string subkeyPath, RegistryAccessRights access, RegistryKeyOptions options, CancellationToken cancellationToken)
		{
			RpcPointer<RpcContextHandle> phkResult = new();
			Win32ErrorCode res = (Win32ErrorCode)await this._owner.proxy.BaseRegOpenKey(this._hkey, (subkeyPath + '\0').ToRpcUnicodeString(), (uint)options, (uint)access, phkResult, cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();

			return new RegistryKey(RegistryPath.GetSubkeyNameFromPath(subkeyPath), RegistryPath.Combine(this.KeyPath, subkeyPath), phkResult.value, this._owner);
		}

		public Task<RegistryKeyInfo> QueryInfo(CancellationToken cancellationToken)
			=> this.QueryInfo(includeClass: true, cancellationToken);

		// includeClass can be false for access-limited keys (TBO enumeration).
		public async Task<RegistryKeyInfo> QueryInfo(bool includeClass, CancellationToken cancellationToken)
		{
			RpcPointer<ms_dtyp.RPC_UNICODE_STRING> lpClassOut = new();
			RpcPointer<uint> lpcSubKeys = new();
			RpcPointer<uint> lpcbMaxSubKeyLen = new();
			RpcPointer<uint> lpcbMaxClassLen = new();
			RpcPointer<uint> lpcValues = new();
			RpcPointer<uint> lpcbMaxValueNameLen = new();
			RpcPointer<uint> lpcbMaxValueLen = new();
			RpcPointer<uint> lpcbSecurityDescriptor = new();
			RpcPointer<ms_dtyp.FILETIME> lpftLastWriteTime = new();
			var classInput = includeClass
				? new ms_dtyp.RPC_UNICODE_STRING
				{
					Buffer = new RpcPointer<ArraySegment<char>>(new ArraySegment<char>(new char[16], 0, 0)),
					Length = 0,
					MaximumLength = 32
				}
				: new ms_dtyp.RPC_UNICODE_STRING();
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegQueryInfoKey(
				this._hkey,
				classInput,
				lpClassOut,
				lpcSubKeys,
				lpcbMaxSubKeyLen,
				lpcbMaxClassLen,
				lpcValues,
				lpcbMaxValueNameLen,
				lpcbMaxValueLen,
				lpcbSecurityDescriptor,
				lpftLastWriteTime,
				cancellationToken
				).ConfigureAwait(false);
			res.CheckAndThrow();

			return new RegistryKeyInfo
			{
				ClassName = includeClass ? lpClassOut.value.AsString() : null,
				SubkeyCount = (int)lpcSubKeys.value,
				MaxSubkeyLength = (int)lpcbMaxSubKeyLen.value,
				MaxClassLength = (int)lpcbMaxClassLen.value,
				ValueCount = (int)lpcValues.value,
				MaxValueNameLength = (int)lpcbMaxValueNameLen.value,
				MaxValueDataLength = (int)lpcbMaxValueLen.value,
				SecurityDescriptorLength = (int)lpcbSecurityDescriptor.value,
				LastWriteTime = lpftLastWriteTime.value.ToDateTime()
			};
		}

		public async Task<byte[]> QuerySecurity(SecurityInfo info, CancellationToken cancellationToken)
		{
			if (info == SecurityInfo.None)
				throw new ArgumentException("Security info must include at least one flag.", nameof(info));

			int bufferSize = DefaultSecurityDescriptorBufferSize;
			try
			{
				var keyInfo = await this.QueryInfo(includeClass: false, cancellationToken).ConfigureAwait(false);
				if (keyInfo.SecurityDescriptorLength > 0)
					bufferSize = Math.Max(bufferSize, keyInfo.SecurityDescriptorLength);
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				// Fallback to the default buffer size when key metadata is access-restricted.
			}

			for (int attempt = 0; attempt < 3; attempt++)
			{
				var buffer = new byte[bufferSize];
				var input = new ms_rrp.RPC_SECURITY_DESCRIPTOR
				{
					// The server treats lpSecurityDescriptor as an output buffer. We send a conformant-varying array header
					// with max_count=buffer.Length but count=0 (no elements), which avoids transmitting a large zero-filled buffer.
					lpSecurityDescriptor = new RpcPointer<ArraySegment<byte>>(new ArraySegment<byte>(buffer, 0, 0)),
					cbInSecurityDescriptor = (uint)bufferSize,
					cbOutSecurityDescriptor = 0
				};

				var output = new RpcPointer<ms_rrp.RPC_SECURITY_DESCRIPTOR>();

				var res = (Win32ErrorCode)await this._owner.proxy.BaseRegGetKeySecurity(
					this._hkey,
					(uint)info,
					input,
					output,
					cancellationToken).ConfigureAwait(false);

				// Some servers appear to validate the embedded array lengths strictly; fall back to the previous behavior.
				if (res == Win32ErrorCode.ERROR_INVALID_PARAMETER && input.lpSecurityDescriptor is not null && input.lpSecurityDescriptor.value.Count == 0)
				{
					input.lpSecurityDescriptor.value = new ArraySegment<byte>(buffer, 0, buffer.Length);
					input.cbOutSecurityDescriptor = (uint)bufferSize;

					res = (Win32ErrorCode)await this._owner.proxy.BaseRegGetKeySecurity(
						this._hkey,
						(uint)info,
						input,
						output,
						cancellationToken).ConfigureAwait(false);
				}

				if (res == Win32ErrorCode.ERROR_INSUFFICIENT_BUFFER || res == Win32ErrorCode.ERROR_MORE_DATA)
				{
					int needed = (int)output.value.cbOutSecurityDescriptor;
					if (needed <= bufferSize)
						needed = bufferSize * 2;
					bufferSize = needed;
					continue;
				}

				res.CheckAndThrow();
				return ExtractSecurityDescriptor(output.value);
			}

			throw new Win32Exception((int)Win32ErrorCode.ERROR_INSUFFICIENT_BUFFER);
		}

		// Added so TBO can set registry key security descriptors over MS-RRP; keep minimal to allow future Titanis SD handling changes.
		public async Task SetSecurity(SecurityInfo info, byte[] securityDescriptor, CancellationToken cancellationToken)
		{
			if (info == SecurityInfo.None)
				throw new ArgumentException("Security info must include at least one flag.", nameof(info));
			if (securityDescriptor == null || securityDescriptor.Length == 0)
				throw new ArgumentException("Security descriptor must be provided.", nameof(securityDescriptor));

			static ms_rrp.RPC_SECURITY_DESCRIPTOR BuildInput(byte[] sd, uint cbOut)
			{
				return new ms_rrp.RPC_SECURITY_DESCRIPTOR
				{
					lpSecurityDescriptor = new RpcPointer<ArraySegment<byte>>(
						new ArraySegment<byte>(sd, 0, sd.Length)),
					cbInSecurityDescriptor = (uint)sd.Length,
					// BaseRegSetKeySecurity treats the security descriptor as input; cbOut is not used.
					// Some servers validate this value strictly and reject non-zero cbOut.
					cbOutSecurityDescriptor = cbOut
				};
			}

			async Task<Win32ErrorCode> TrySetSecurity(SecurityInfo flags, uint cbOut)
			{
				var input = BuildInput(securityDescriptor, cbOut);
				return (Win32ErrorCode)await this._owner.proxy.BaseRegSetKeySecurity(
					this._hkey,
					(uint)flags,
					input,
					cancellationToken).ConfigureAwait(false);
			}

			// Prefer cbOut=0 for set operations. Fall back to cbOut=cbIn if a server rejects the input marshalling.
			var res = await TrySetSecurity(info, cbOut: 0).ConfigureAwait(false);
			if (res == Win32ErrorCode.ERROR_INVALID_PARAMETER)
				res = await TrySetSecurity(info, cbOut: (uint)securityDescriptor.Length).ConfigureAwait(false);

			// Some servers require BACKUP_SECURITY_INFORMATION to honor SeRestorePrivilege for SetKeySecurity.
			// Retry once with BACKUP_SECURITY_INFORMATION if access is denied and the caller didn't request it.
			if (res == Win32ErrorCode.ERROR_ACCESS_DENIED && !info.HasFlag(SecurityInfo.Backup))
			{
				var backupInfo = info | SecurityInfo.Backup;
				res = await TrySetSecurity(backupInfo, cbOut: 0).ConfigureAwait(false);
				if (res == Win32ErrorCode.ERROR_INVALID_PARAMETER)
					res = await TrySetSecurity(backupInfo, cbOut: (uint)securityDescriptor.Length).ConfigureAwait(false);
			}

			res.CheckAndThrow();
		}

		private static byte[] ExtractSecurityDescriptor(ms_rrp.RPC_SECURITY_DESCRIPTOR descriptor)
		{
			if (descriptor.lpSecurityDescriptor == null)
				return Array.Empty<byte>();

			var segment = descriptor.lpSecurityDescriptor.value;
			var data = segment.Array;
			if (data == null)
				return Array.Empty<byte>();

			int length = (int)descriptor.cbOutSecurityDescriptor;
			if (length <= 0 || length > segment.Count)
				length = segment.Count;

			var result = new byte[length];
			Array.Copy(data, segment.Offset, result, 0, length);
			return result;
		}

		public async Task SaveKey(string fileName, RegistrySaveFormat format, CancellationToken cancellationToken)
		{
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegSaveKeyEx(
				this._hkey,
				fileName.ToRpcUnicodeString(),
				null,
				(uint)format,
				cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();
		}

		public async IAsyncEnumerable<RegistrySubkeyInfo> GetSubkeyNames(CancellationToken cancellationToken)
		{
			RegistryKeyInfo? keyInfo;
			try
			{
				keyInfo = await this.QueryInfo(cancellationToken).ConfigureAwait(false);
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				// TBO needs to enumerate subkeys even when class metadata is access-restricted.
				keyInfo = null;
			}

			if (keyInfo != null)
			{
				int index = 0;
				Win32ErrorCode res;
				ms_dtyp.RPC_UNICODE_STRING lpNameIn = new() { MaximumLength = (ushort)(keyInfo.MaxSubkeyLength * 2) };
				RpcPointer<ms_dtyp.RPC_UNICODE_STRING> lpNameOut = new();
				RpcPointer<ms_dtyp.RPC_UNICODE_STRING> lpClassIn = new(new ms_dtyp.RPC_UNICODE_STRING() { MaximumLength = (ushort)(keyInfo.MaxClassLength * 2) });
				RpcPointer<RpcPointer<ms_dtyp.RPC_UNICODE_STRING>> lplpClassOut = new();
				while ((res = (Win32ErrorCode)await this._owner.proxy.BaseRegEnumKey(
						this._hkey,
						(uint)index++,
						lpNameIn,
						lpNameOut,
						lpClassIn,
						lplpClassOut,
						new RpcPointer<ms_dtyp.FILETIME>(),
						cancellationToken
						).ConfigureAwait(false)) == Win32ErrorCode.ERROR_SUCCESS)
				{
					var name = lpNameOut.value.AsString().TrimEnd('\0');
					var className = lplpClassOut.value.value.AsString()?.TrimEnd('\0');

					yield return new RegistrySubkeyInfo(name, className);
				}

				if (res is not Win32ErrorCode.ERROR_SUCCESS and not Win32ErrorCode.ERROR_NO_MORE_ITEMS)
					res.CheckAndThrow();

				yield break;
			}

			// Fallback enumeration without class info.
			int nameChars = 256;
			int indexFallback = 0;
			while (true)
			{
				Win32ErrorCode res;
				while (true)
				{
					var nameBuffer = new char[nameChars];
					ms_dtyp.RPC_UNICODE_STRING lpNameIn = new()
					{
						MaximumLength = (ushort)(nameChars * 2),
						Buffer = new RpcPointer<ArraySegment<char>>(new ArraySegment<char>(nameBuffer, 0, 0))
					};
					RpcPointer<ms_dtyp.RPC_UNICODE_STRING> lpNameOut = new();
					RpcPointer<ms_dtyp.RPC_UNICODE_STRING> lpClassIn = new(new ms_dtyp.RPC_UNICODE_STRING());
					RpcPointer<RpcPointer<ms_dtyp.RPC_UNICODE_STRING>> lplpClassOut = new();

					res = (Win32ErrorCode)await this._owner.proxy.BaseRegEnumKey(
						this._hkey,
						(uint)indexFallback,
						lpNameIn,
						lpNameOut,
						lpClassIn,
						lplpClassOut,
						new RpcPointer<ms_dtyp.FILETIME>(),
						cancellationToken
						).ConfigureAwait(false);

					if (res == Win32ErrorCode.ERROR_MORE_DATA)
					{
						nameChars *= 2;
						continue;
					}

					if (res == Win32ErrorCode.ERROR_SUCCESS)
					{
						var name = lpNameOut.value.AsString().TrimEnd('\0');
						yield return new RegistrySubkeyInfo(name, null);
					}

					break;
				}

				if (res == Win32ErrorCode.ERROR_SUCCESS)
				{
					indexFallback++;
					continue;
				}

				if (res == Win32ErrorCode.ERROR_NO_MORE_ITEMS)
					yield break;

				res.CheckAndThrow();
			}
		}

		public IAsyncEnumerable<RegistryValueInfo> GetValueNames(CancellationToken cancellationToken) => this.GetValues(false, cancellationToken);
		public async IAsyncEnumerable<RegistryValueInfo> GetValues(bool includeData, CancellationToken cancellationToken)
		{
			var keyInfo = await this.QueryInfo(cancellationToken).ConfigureAwait(false);
			if (keyInfo.ValueCount == 0)
				yield break;

			int valueNameChars = Math.Max(1, keyInfo.MaxValueNameLength + 1);
			int cbBuffer = includeData ? Math.Max(1, keyInfo.MaxValueDataLength) : 0;

			int index = 0;
			Win32ErrorCode res;
			RpcPointer<ms_dtyp.RPC_UNICODE_STRING> lpValueNameOut = new();
			RpcPointer<uint> lpType = new();

			byte[] stubBuffer = includeData ? new byte[cbBuffer] : Array.Empty<byte>();
			RpcPointer<ArraySegment<byte>> lpData = includeData ? new(new ArraySegment<byte>(stubBuffer, 0, 0)) : null;

			ms_dtyp.RPC_UNICODE_STRING lpValueNameIn = new()
			{
				MaximumLength = (ushort)(valueNameChars * 2),
				Buffer = new RpcPointer<ArraySegment<char>>(new ArraySegment<char>(new char[valueNameChars], 0, 0))
			};
			RpcPointer<uint> lpcbData = new(includeData ? (uint)cbBuffer : 0);
			RpcPointer<uint> lpcbLen = new(0U);
			while ((res = (Win32ErrorCode)await this._owner.proxy.BaseRegEnumValue(
					this._hkey,
					(uint)index,
					lpValueNameIn,
					lpValueNameOut,
					lpType,
					lpData,
					lpcbData,
					lpcbLen,
					cancellationToken
					).ConfigureAwait(false)) == Win32ErrorCode.ERROR_SUCCESS)
			{
				var valueBuf = lpData?.value.Array;
				var data = (valueBuf != null) ? valueBuf.AsSpan(0, Math.Min((int)lpcbLen.value, cbBuffer)).ToArray() : null;

				yield return new RegistryValueInfo(
					lpValueNameOut.value.AsString(true) ?? string.Empty,
					(RegistryValueType)lpType.value,
					(int)lpcbLen.value,
					data,
					TryDecodeValue((RegistryValueType)lpType.value, data)
					);

				index++;

				if (includeData)
					lpData.value = (new ArraySegment<byte>(stubBuffer, 0, 0));
				lpcbData.value = includeData ? (uint)cbBuffer : 0;
				lpcbLen.value = 0U;
			}

			if (res is not Win32ErrorCode.ERROR_SUCCESS and not Win32ErrorCode.ERROR_NO_MORE_ITEMS)
				res.CheckAndThrow();
		}

		public async Task<SecurityDescriptor> GetSecurityDescriptor(SecurityInfo securityInfo, CancellationToken cancellationToken)
		{
			RpcPointer<ms_rrp.RPC_SECURITY_DESCRIPTOR> pRpcSecurityDescriptorOut = new();
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegGetKeySecurity(
				this._hkey,
				(uint)securityInfo,
				default,
				pRpcSecurityDescriptorOut,
				cancellationToken).ConfigureAwait(false);
			if (res is Win32ErrorCode.ERROR_INSUFFICIENT_BUFFER)
			{
				pRpcSecurityDescriptorOut = new RpcPointer<ms_rrp.RPC_SECURITY_DESCRIPTOR>(new ms_rrp.RPC_SECURITY_DESCRIPTOR
				{
					cbInSecurityDescriptor = pRpcSecurityDescriptorOut.value.cbInSecurityDescriptor,
					lpSecurityDescriptor = new RpcPointer<ArraySegment<byte>>(new ArraySegment<byte>(new byte[pRpcSecurityDescriptorOut.value.cbInSecurityDescriptor], 0, 0))
				});
				res = (Win32ErrorCode)await this._owner.proxy.BaseRegGetKeySecurity(
					this._hkey,
					(uint)securityInfo,
					pRpcSecurityDescriptorOut.value,
					pRpcSecurityDescriptorOut,
					cancellationToken).ConfigureAwait(false);
			}

			if (res is not Win32ErrorCode.ERROR_SUCCESS)
				res.CheckAndThrow();

			return new SecurityDescriptor(pRpcSecurityDescriptorOut.value.lpSecurityDescriptor.value);
		}
		public async Task<SecurityDescriptor> SetSecurityDescriptor(SecurityInfo securityInfo, SecurityDescriptor sd, CancellationToken cancellationToken)
		{
			ArgumentNullException.ThrowIfNull(sd);

			var sdBytes = sd.ToByteArray();

			RpcPointer<ms_rrp.RPC_SECURITY_DESCRIPTOR> pRpcSecurityDescriptorOut = new();
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegSetKeySecurity(
				this._hkey,
				(uint)securityInfo,
				new ms_rrp.RPC_SECURITY_DESCRIPTOR
				{
					cbInSecurityDescriptor = (uint)sdBytes.Length,
					cbOutSecurityDescriptor = (uint)sdBytes.Length,
					lpSecurityDescriptor = new RpcPointer<ArraySegment<byte>>(sdBytes)
				},
				cancellationToken).ConfigureAwait(false);

			if (res is not Win32ErrorCode.ERROR_SUCCESS)
				res.CheckAndThrow();

			return new SecurityDescriptor(pRpcSecurityDescriptorOut.value.lpSecurityDescriptor.value);
		}

		public async Task<RegistryValueInfo> GetValue(string? name, CancellationToken cancellationToken)
		{
			uint len = 0;

			RpcPointer<uint> lpType = new();
			ms_dtyp.RPC_UNICODE_STRING lpValueName = string.IsNullOrEmpty(name) ? new ms_dtyp.RPC_UNICODE_STRING
			{
				Buffer = new RpcPointer<ArraySegment<char>>(new char[1]),
				Length = 2,
				MaximumLength = 2,
			} : (name + '\0').ToRpcUnicodeString();
			//ms_dtyp.RPC_UNICODE_STRING lpValueName = name.ToRpcUnicodeString();
			RpcPointer<uint> lpcbLen = new(0U);
			RpcPointer<uint> lpcbData = new(len);
			RpcPointer<ArraySegment<byte>> lpData = new(new ArraySegment<byte>(new byte[len], 0, 0));
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegQueryValue(
				this._hkey,
				lpValueName,
				lpType,
				lpData,
				lpcbData,
				lpcbLen,
				cancellationToken).ConfigureAwait(false);

			if (res is Win32ErrorCode.ERROR_MORE_DATA)
			{
				lpData.value = new ArraySegment<byte>(new byte[lpcbData.value], 0, 0);
				lpcbLen.value = 0;
				res = (Win32ErrorCode)await this._owner.proxy.BaseRegQueryValue(
					this._hkey,
					lpValueName,
					lpType,
					lpData,
					lpcbData,
					lpcbLen,
					cancellationToken).ConfigureAwait(false);
			}

			if (res is not Win32ErrorCode.ERROR_SUCCESS)
				res.CheckAndThrow();

			byte[]? data = lpData.value.Array;
			if (data != null && lpcbLen.value < data.Length)
				Array.Resize(ref data, (int)lpcbLen.value);
			var valueType = (RegistryValueType)lpType.value;
			return new RegistryValueInfo(name ?? string.Empty, valueType, 0, data, TryDecodeValue(valueType, data));
		}

		internal static object? TryDecodeValue(RegistryValueType valueType, byte[]? data)
		{
			if (data is null)
				return null;

			return (valueType, data.Length) switch
			{
				(RegistryValueType.Qword, 8) => BinaryPrimitives.ReadUInt64LittleEndian(data),
				(RegistryValueType.DwordLE, 4) => BinaryPrimitives.ReadUInt32LittleEndian(data),
				(RegistryValueType.DwordBE, 4) => BinaryPrimitives.ReadUInt32BigEndian(data),
				(RegistryValueType.String, _) => TryDecodeUtf16String(data),
				(RegistryValueType.MultiString, _) => TryDecodeUtf16MultiString(data),
				(RegistryValueType.Binary, _) => null,
				_ => null
			};
		}

		private static string? TryDecodeUtf16String(byte[] bytes)
		{
			int length = bytes.Length;

			if ((length % 2) != 0)
				return null;

			if (length >= 2 && bytes[^1] == 0 && bytes[^2] == 0)
				length -= 2;

			try
			{
				var str = Encoding.Unicode.GetString(bytes, 0, length);
				return str;
			}
			catch
			{
				return null;
			}
		}

		private static string[]? TryDecodeUtf16MultiString(byte[] bytes)
		{
			int startIndex = 0;
			List<string> strs = new List<string>();

			for (int i = 2; i < bytes.Length; i += 2)
			{
				var c = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i - 2, 2));
				if (c == 0)
				{
					try
					{
						strs.Add(Encoding.Unicode.GetString(bytes.AsSpan(startIndex, i - startIndex - 2)));
					}
					catch
					{
						return null;
					}
					startIndex = i;
				}
			}

			return strs.ToArray();
		}
	}

	partial class RegistryKey : IRegistryKey, IDisposable, IAsyncDisposable
	{
		private bool disposedValue;

		protected virtual void Dispose(bool disposing)
		{
			if (!disposedValue)
			{
				if (disposing)
				{
					_ = this.Close(CancellationToken.None);
				}

				// TODO: free unmanaged resources (unmanaged objects) and override finalizer
				// TODO: set large fields to null
				disposedValue = true;
			}
		}

		public void Dispose()
		{
			// Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}

		public Task Close(CancellationToken cancellationToken)
		{
			return this._owner.proxy.BaseRegCloseKey(new RpcPointer<RpcContextHandle>(this._hkey), cancellationToken);
		}

		public async ValueTask DisposeAsync()
		{
			await this.Close(CancellationToken.None).ConfigureAwait(false);
		}
	}
}
