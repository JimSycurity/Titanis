using System;
using System.Threading;
using System.Threading.Tasks;
using Titanis.DceRpc;
using Titanis.Winterop;

namespace Titanis.Msrpc.Msrrp
{
	// Mutation helpers used by TBO remote registry cmdlets/provider.
	public partial class RegistryKey
	{
		public async Task<RegistryKey> CreateSubkey(
			string subkeyPath,
			RegistryAccessRights access,
			RegistryKeyOptions options,
			CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(subkeyPath))
				throw new ArgumentException("Subkey path must be provided.", nameof(subkeyPath));

			RpcPointer<RpcContextHandle> phkResult = new();
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegCreateKey(
				this._hkey,
				(subkeyPath + '\0').ToRpcUnicodeString(),
				string.Empty.ToRpcUnicodeString(),
				(uint)options,
				(uint)access,
				null,
				phkResult,
				null,
				cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();

			return new RegistryKey(RegistryPath.GetSubkeyNameFromPath(subkeyPath), RegistryPath.Combine(this.KeyPath, subkeyPath), phkResult.value, this._owner);
		}

		public async Task DeleteSubkey(string subkeyPath, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(subkeyPath))
				throw new ArgumentException("Subkey path must be provided.", nameof(subkeyPath));

			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegDeleteKey(
				this._hkey,
				(subkeyPath + '\0').ToRpcUnicodeString(),
				cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();
		}

		public async Task DeleteValue(string? name, CancellationToken cancellationToken)
		{
			var valueName = BuildValueName(name);
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegDeleteValue(
				this._hkey,
				valueName,
				cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();
		}

		public async Task SetValue(
			string? name,
			RegistryValueType valueType,
			byte[]? data,
			CancellationToken cancellationToken)
		{
			var valueName = BuildValueName(name);
			byte[] payload = data ?? Array.Empty<byte>();
			var res = (Win32ErrorCode)await this._owner.proxy.BaseRegSetValue(
				this._hkey,
				valueName,
				(uint)valueType,
				payload,
				(uint)payload.Length,
				cancellationToken).ConfigureAwait(false);
			res.CheckAndThrow();
		}

		private static ms_dtyp.RPC_UNICODE_STRING BuildValueName(string? name)
		{
			if (string.IsNullOrEmpty(name))
			{
				return new ms_dtyp.RPC_UNICODE_STRING
				{
					Buffer = new RpcPointer<ArraySegment<char>>(new char[1]),
					Length = 2,
					MaximumLength = 2,
				};
			}

			return (name + '\0').ToRpcUnicodeString();
		}
	}
}
