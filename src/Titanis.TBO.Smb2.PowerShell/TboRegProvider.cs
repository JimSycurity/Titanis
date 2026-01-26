using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegHiveItem
	{
		public TboRegHiveItem(string serverName, RegistryRootKey rootKey)
		{
			this.ServerName = serverName;
			this.RootKey = rootKey;
			this.Name = RemoteRegistryClient.GetRootName(rootKey);
		}

		public string ServerName { get; }
		public RegistryRootKey RootKey { get; }
		public string Name { get; }
		public string KeyPath => this.Name;
	}

	internal sealed class TboRegDriveInfo : PSDriveInfo
	{
		internal TboRegDriveInfo(PSDriveInfo driveInfo, string serverName)
			: base(driveInfo)
		{
			this.ServerName = serverName;
		}

		public string ServerName { get; }
	}

	/// <summary>
	/// Implements a <see cref="NavigationCmdletProvider"/> for remote registry access.
	/// </summary>
	[CmdletProvider(ProviderName, ProviderCapabilities.None)]
	public sealed class TboRegProvider : NavigationCmdletProvider
	{
		public const string ProviderName = "TBO.Reg";
		private const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;
		private const string DefaultValueName = "(Default)";

		private static readonly RegistryRootKey[] RootKeys = new[]
		{
			RegistryRootKey.ClassesRoot,
			RegistryRootKey.CurrentUser,
			RegistryRootKey.LocalMachine,
			RegistryRootKey.Users,
			RegistryRootKey.CurrentConfig,
			RegistryRootKey.PerformanceData,
			RegistryRootKey.PerformanceText,
			RegistryRootKey.PerformanceNlsText
		};

		private CancellationTokenSource? _cancelSource;

		protected override Collection<PSDriveInfo> InitializeDefaultDrives()
			=> new Collection<PSDriveInfo>();

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
		}

		private void BeginOperation(Action<CancellationToken> action)
		{
			var prevSource = this._cancelSource;
			var cancelSource = prevSource ??= (this._cancelSource = new CancellationTokenSource());

			try
			{
				action(cancelSource.Token);
			}
			finally
			{
				this._cancelSource = prevSource;
			}
		}

		private TResult BeginOperation<TResult>(Func<CancellationToken, TResult> func)
		{
			var prevSource = this._cancelSource;
			var cancelSource = prevSource ??= (this._cancelSource = new CancellationTokenSource());

			try
			{
				return func(cancelSource.Token);
			}
			finally
			{
				this._cancelSource = prevSource;
			}
		}

		protected override object NewDriveDynamicParameters()
			=> new SmbConnectionParameters();

		protected override PSDriveInfo NewDrive(PSDriveInfo drive)
		{
			var serverName = NormalizeServerName(drive.Root);
			var smb = GetSmbProviderInfo();

			var baseParms = smb.GetConnectParametersFor(serverName, true);
			var parms = this.DynamicParameters as SmbConnectionParameters;
			if (parms != null)
			{
				parms = parms.MergeOnto(baseParms ?? SmbConnectionParameters.GetDefault());
				smb.SetConnectParameters(serverName, parms);
			}

			return new TboRegDriveInfo(drive, serverName);
		}

		protected override bool IsValidPath(string path)
		{
			if (string.IsNullOrWhiteSpace(path))
				return true;

			var normalized = path.Trim().TrimStart('\\');
			if (string.IsNullOrEmpty(normalized))
				return true;

			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			return RemoteRegistryClient.TryResolveRootKey(rootPart) != RegistryRootKey.Invalid;
		}

		protected override bool IsItemContainer(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				return true;

			return this.BeginOperation(token =>
			{
				using var session = OpenRegistrySession(drive.ServerName, token);
				return TryOpenKey(session.Client, RegistryPathParser.Parse(providerPath, nameof(path)), RegistryAccessRights.QueryValue, token) != null;
			});
		}

		protected override bool ItemExists(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath) || IsHivePath(providerPath))
				return true;

			return this.BeginOperation(token =>
			{
				using var session = OpenRegistrySession(drive.ServerName, token);
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));

				using var key = TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue, token);
				if (key != null)
					return true;

				return TryValueExists(session.Client, parsed, token);
			});
		}

		protected override void GetItem(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath))
				return;

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				if (parsed.IsRoot)
				{
					var item = new TboRegHiveItem(drive.ServerName, parsed.RootKey);
					this.WriteItemObject(item, parsed.RootName, true);
					return;
				}

				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = TryOpenKey(session.Client, parsed, RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys, token);
				if (key != null)
				{
					var info = key.QueryInfo(token).GetAwaiter().GetResult();
					this.WriteItemObject(new TboRegistryKeyInfo(drive.ServerName, parsed.KeyPath, info), parsed.KeyPath, true);
					return;
				}

				if (TryGetValue(session.Client, parsed, token, out var valueInfo, out var parentKeyPath))
				{
					var itemPath = CombineProviderPath(parentKeyPath, NormalizeValueName(valueInfo.Name));
					this.WriteItemObject(new TboRegistryValueInfo(drive.ServerName, parentKeyPath, valueInfo), itemPath, false);
					return;
				}

				throw new ItemNotFoundException($"Registry path not found: {parsed.KeyPath}");
			});
		}

		protected override void GetChildItems(string path, bool recurse)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath))
			{
				foreach (var rootKey in RootKeys)
				{
					var item = new TboRegHiveItem(drive.ServerName, rootKey);
					this.WriteItemObject(item, item.Name, true);
				}
				return;
			}

			this.BeginOperation(token =>
			{
				var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
				using var session = OpenRegistrySession(drive.ServerName, token);
				using var key = OpenRegistryKey(session.Client, parsed, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, token);

				foreach (var subkey in EnumerateSubkeys(key, token))
				{
					var item = new TboRegistrySubkeyInfo(drive.ServerName, parsed.KeyPath, subkey);
					this.WriteItemObject(item, item.KeyPath, true);
				}

				foreach (var value in EnumerateValues(key, token))
				{
					var normalizedName = NormalizeValueName(value.Name);
					var valueInfo = new TboRegistryValueInfo(drive.ServerName, parsed.KeyPath, value);
					this.WriteItemObject(valueInfo, CombineProviderPath(parsed.KeyPath, normalizedName), false);
				}
			});
		}

		private static bool IsRootPath(string providerPath)
			=> string.IsNullOrWhiteSpace(providerPath) || providerPath == "\\";

		private static bool IsHivePath(string providerPath)
		{
			if (string.IsNullOrWhiteSpace(providerPath))
				return false;

			var normalized = providerPath.TrimStart('\\');
			string rootPart = normalized.Split('\\', 2)[0].TrimEnd(':');
			if (RemoteRegistryClient.TryResolveRootKey(rootPart) == RegistryRootKey.Invalid)
				return false;

			return normalized.IndexOf('\\') < 0;
		}

		private static string CombineProviderPath(string basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private static string NormalizeValueName(string name)
			=> string.IsNullOrEmpty(name) ? DefaultValueName : name;

		private static string DenormalizeValueName(string name)
			=> string.Equals(name, DefaultValueName, StringComparison.OrdinalIgnoreCase) ? string.Empty : name;

		private static string NormalizeServerName(string root)
		{
			if (string.IsNullOrWhiteSpace(root))
				throw new ArgumentException("Drive root must be a server name.", nameof(root));

			var trimmed = root.Trim();
			if (trimmed.StartsWith(@"\\", StringComparison.Ordinal))
			{
				if (UncPath.TryParse(trimmed, out var unc) && unc != null)
				{
					if (!string.IsNullOrEmpty(unc.ShareName))
						throw new ArgumentException("Drive root must be a server name, not a UNC share.", nameof(root));
					return unc.ServerName;
				}

				trimmed = trimmed.TrimStart('\\');
			}

			return trimmed.TrimEnd('\\');
		}

		private string ResolveProviderPath(string path, out TboRegDriveInfo driveInfo)
		{
			ProviderInfo? providerInfo;
			PSDriveInfo? drive;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out drive);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", nameof(path), ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a {ProviderName} PSDrive path: {path}", nameof(path));

			driveInfo = drive as TboRegDriveInfo
				?? throw new ArgumentException($"Path must be a {ProviderName} PSDrive path: {path}", nameof(path));

			providerPath = providerPath.TrimStart('\\');
			var root = driveInfo.Root?.TrimStart('\\').TrimEnd('\\');
			if (!string.IsNullOrEmpty(root))
			{
				if (providerPath.Equals(root, StringComparison.OrdinalIgnoreCase))
					return string.Empty;

				var prefix = root + "\\";
				if (providerPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
					providerPath = providerPath.Substring(prefix.Length);
			}

			return providerPath;
		}

		private SmbProviderInfo GetSmbProviderInfo()
			=> (SmbProviderInfo)this.SessionState.Provider.GetOne(SmbProvider.ProviderName);

		private RemoteRegistrySession OpenRegistrySession(string serverName, CancellationToken cancellationToken)
		{
			var smb = GetSmbProviderInfo();
			return smb.OpenRemoteRegistrySessionAsync(serverName, cancellationToken).GetAwaiter().GetResult();
		}

		private static RegistryKey OpenRegistryKey(
			RemoteRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
		{
			var baseAccess = path.IsRoot ? access : RegistryAccessRights.EnumerateSubkeys | access;
			var rootKey = client.OpenRootKey(path.RootKey, baseAccess, cancellationToken).GetAwaiter().GetResult();
			if (path.IsRoot)
				return rootKey;

			var subkeyPath = path.SubkeyPath ?? string.Empty;
			try
			{
				var key = rootKey.OpenSubkey(subkeyPath, access, BackupOptions, cancellationToken).GetAwaiter().GetResult();
				rootKey.Dispose();
				return key;
			}
			catch
			{
				rootKey.Dispose();
				throw;
			}
		}

		private static RegistryKey? TryOpenKey(
			RemoteRegistryClient client,
			RegistryPathSpec path,
			RegistryAccessRights access,
			CancellationToken cancellationToken)
		{
			try
			{
				return OpenRegistryKey(client, path, access, cancellationToken);
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME)
			{
				return null;
			}
		}

		private static IEnumerable<RegistrySubkeyInfo> EnumerateSubkeys(RegistryKey key, CancellationToken cancellationToken)
		{
			var enumerator = key.GetSubkeyNames(cancellationToken).GetAsyncEnumerator();
			try
			{
				while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
					yield return enumerator.Current;
			}
			finally
			{
				try
				{
					enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
				catch (NotSupportedException)
				{
				}
			}
		}

		private static IEnumerable<RegistryValueInfo> EnumerateValues(RegistryKey key, CancellationToken cancellationToken)
		{
			var enumerator = key.GetValues(includeData: false, cancellationToken).GetAsyncEnumerator();
			try
			{
				while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
					yield return enumerator.Current;
			}
			finally
			{
				try
				{
					enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
				}
				catch (NotSupportedException)
				{
				}
			}
		}

		private static bool TryValueExists(RemoteRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken)
		{
			if (string.IsNullOrEmpty(path.SubkeyPath))
				return false;

			var parentSubkey = RegistryPath.GetParentKeyNameFromPath(path.SubkeyPath);
			var valueName = RegistryPath.GetSubkeyNameFromPath(path.SubkeyPath);
			var parentSpec = new RegistryPathSpec(path.RootKey, path.RootName, parentSubkey);

			try
			{
				using var parentKey = OpenRegistryKey(client, parentSpec, RegistryAccessRights.QueryValue, cancellationToken);
				valueName = DenormalizeValueName(valueName);
				parentKey.GetValue(valueName, cancellationToken).GetAwaiter().GetResult();
				return true;
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND)
			{
				return false;
			}
		}

		private static bool TryGetValue(RemoteRegistryClient client, RegistryPathSpec path, CancellationToken cancellationToken, out RegistryValueInfo info, out string keyPath)
		{
			info = null!;
			keyPath = string.Empty;
			if (string.IsNullOrEmpty(path.SubkeyPath))
				return false;

			var parentSubkey = RegistryPath.GetParentKeyNameFromPath(path.SubkeyPath);
			var valueName = RegistryPath.GetSubkeyNameFromPath(path.SubkeyPath);
			var parentSpec = new RegistryPathSpec(path.RootKey, path.RootName, parentSubkey);

			try
			{
				using var parentKey = OpenRegistryKey(client, parentSpec, RegistryAccessRights.QueryValue, cancellationToken);
				valueName = DenormalizeValueName(valueName);
				info = parentKey.GetValue(valueName, cancellationToken).GetAwaiter().GetResult();
				keyPath = parentSpec.KeyPath;
				return true;
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND)
			{
				return false;
			}
		}
	}
}
