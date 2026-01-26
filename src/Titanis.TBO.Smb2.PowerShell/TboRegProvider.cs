using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Provider;
using Titanis;
using Titanis.Msrpc.Msrrp;

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

		protected override Collection<PSDriveInfo> InitializeDefaultDrives()
			=> new Collection<PSDriveInfo>();

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
			var providerPath = ResolveProviderPath(path, out _);
			return IsRootPath(providerPath) || IsHivePath(providerPath);
		}

		protected override bool ItemExists(string path)
		{
			var providerPath = ResolveProviderPath(path, out _);
			return IsRootPath(providerPath) || IsHivePath(providerPath);
		}

		protected override void GetItem(string path)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (IsRootPath(providerPath))
				return;

			var parsed = RegistryPathParser.Parse(providerPath, nameof(path));
			if (!parsed.IsRoot)
				throw new NotSupportedException("Registry key lookup is not implemented yet.");
			var rootKey = parsed.RootKey;
			var item = new TboRegHiveItem(drive.ServerName, rootKey);
			this.WriteItemObject(item, parsed.RootName, true);
		}

		protected override void GetChildItems(string path, bool recurse)
		{
			var providerPath = ResolveProviderPath(path, out var drive);
			if (!IsRootPath(providerPath))
				throw new NotSupportedException("Registry key enumeration is not implemented yet.");

			foreach (var rootKey in RootKeys)
			{
				var item = new TboRegHiveItem(drive.ServerName, rootKey);
				this.WriteItemObject(item, item.Name, true);
			}
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

			return providerPath.TrimStart('\\');
		}

		private SmbProviderInfo GetSmbProviderInfo()
			=> (SmbProviderInfo)this.SessionState.Provider.GetOne(SmbProvider.ProviderName);
	}
}
