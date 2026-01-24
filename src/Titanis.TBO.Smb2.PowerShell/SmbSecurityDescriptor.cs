using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBOSmbSecurityDescriptor")]
	public sealed class GetTBOSmbSecurityDescriptor : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";
		private const int DefaultSecurityDescriptorBufferSize = 8192;

		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string[] Path { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string[] LiteralPath { get; set; } = Array.Empty<string>();

		[Parameter]
		public SwitchParameter AsSddl { get; set; }

		[Parameter]
		public SwitchParameter AsBytes { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var format = SecurityDescriptorHelpers.ResolveFormat(this.AsSddl, this.AsBytes, asWindows: false);

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				var securityDescriptor = ReadSecurityDescriptor(smb, uncPath, this._cancelSource.Token);
				if (securityDescriptor == null)
				{
					this.WriteWarning($"No security descriptor was returned for '{uncPath}'.");
					continue;
				}

				this.WriteObject(SecurityDescriptorHelpers.Format(securityDescriptor, format));
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private IEnumerable<string> GetTargetPaths()
		{
			return this.ParameterSetName == LiteralPathParameterSet
				? this.LiteralPath
				: this.Path;
		}

		private SecurityDescriptor? ReadSecurityDescriptor(
			SmbProviderInfo smb,
			UncPath uncPath,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.ReadControl,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
				return file.GetSecurityAsync(
					SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl,
					DefaultSecurityDescriptorBufferSize,
					cancellationToken).GetAwaiter().GetResult();
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}
	}

	[Cmdlet(VerbsCommon.Set, "TBOSmbSecurityDescriptor")]
	public sealed class SetTBOSmbSecurityDescriptor : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";
		private const SecurityInfo DefaultSecurityInfo = SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl;

		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string[] Path { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string[] LiteralPath { get; set; } = Array.Empty<string>();

		[Parameter(Mandatory = true, Position = 1)]
		public SecurityDescriptor SecurityDescriptor { get; set; } = null!;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();

			foreach (var path in GetTargetPaths())
			{
				var uncPath = ResolveToUncPath(path, this.ParameterSetName);
				WriteSecurityDescriptor(smb, uncPath, this._cancelSource.Token);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private IEnumerable<string> GetTargetPaths()
		{
			return this.ParameterSetName == LiteralPathParameterSet
				? this.LiteralPath
				: this.Path;
		}

		private void WriteSecurityDescriptor(
			SmbProviderInfo smb,
			UncPath uncPath,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)(Smb2AccessRights.WriteDac | Smb2AccessRights.WriteOwner | Smb2AccessRights.ReadControl),
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.ReadWrite, cancellationToken).GetAwaiter().GetResult();
				file.SetSecurityAsync(this.SecurityDescriptor, DefaultSecurityInfo, cancellationToken).GetAwaiter().GetResult();
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}
	}
}
