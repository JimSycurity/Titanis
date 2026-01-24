using System;
using System.IO;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Titanis.IO;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Smb2FileBasicInfo = Titanis.Smb2.Pdus.FileBasicInfo;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Copy, "TBOSmbItem")]
	public sealed class CopyTBOSmbItem : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public string Source { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true)]
		public string Destination { get; set; } = string.Empty;

		[Parameter]
		public SwitchParameter Force { get; set; }

		[Parameter]
		public SwitchParameter PreserveTimestamps { get; set; }

		[Parameter]
		public SwitchParameter PreserveSecurityDescriptor { get; set; }

		[Parameter]
		public int ChunkSize { get; set; } = Smb2Client.DefaultChunkSize;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			CopyAsync(smb, this._cancelSource.Token).ConfigureAwait(false).GetAwaiter().GetResult();
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private async Task CopyAsync(SmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (!UncPath.TryParse(this.Source, out var sourcePath) || sourcePath == null)
				throw new ArgumentException($"Source path must be a UNC path: {this.Source}", nameof(Source));
			if (!UncPath.TryParse(this.Destination, out var destinationPath) || destinationPath == null)
				throw new ArgumentException($"Destination path must be a UNC path: {this.Destination}", nameof(Destination));

			var sourceRelativePath = sourcePath.ShareRelativePath;
			if (string.IsNullOrEmpty(sourceRelativePath))
				throw new ArgumentException($"Source path must include a file name: {this.Source}", nameof(Source));

			var smbClient = smb.SmbClient;

			Smb2OpenFile? sourceFile = null;
			Smb2OpenFile? destFile = null;
			try
			{
				sourceFile = await smbClient.OpenFileReadAsync(sourcePath, cancellationToken).ConfigureAwait(false);
				if (sourceFile.IsDirectory)
					throw new IOException($"Source path '{sourcePath}' is a directory. Copy-TBOSmbItem supports files only.");

			var resolvedDest = await ResolveDestinationAsync(smbClient, sourcePath, destinationPath, cancellationToken).ConfigureAwait(false);
			destinationPath = resolvedDest.Path;

				if (resolvedDest.Exists && !this.Force.IsPresent)
					throw new IOException($"The file '{destinationPath}' already exists.");

				Smb2FileBasicInfo? sourceBasicInfo = null;
				if (this.PreserveTimestamps.IsPresent)
					sourceBasicInfo = await sourceFile.GetBasicInfoAsync(cancellationToken).ConfigureAwait(false);

				SecurityDescriptor? sourceSecurityDescriptor = null;
				if (this.PreserveSecurityDescriptor.IsPresent)
				{
					sourceSecurityDescriptor = await sourceFile.GetSecurityAsync(
						SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl | SecurityInfo.Sacl,
						8192,
						cancellationToken).ConfigureAwait(false);
				}

				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = GetCreateDisposition(resolvedDest.Exists, this.PreserveSecurityDescriptor.IsPresent),
					DesiredAccess = (uint)Smb2AccessRights.DefaultCreateAccess,
					ShareAccess = Smb2ShareAccess.ReadWrite,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				if (sourceSecurityDescriptor != null)
					createInfo.SecurityDescriptor = sourceSecurityDescriptor.ToByteArray();

				destFile = (Smb2OpenFile)await smbClient.CreateFileAsync(
					destinationPath,
					createInfo,
					FileAccess.ReadWrite,
					cancellationToken).ConfigureAwait(false);

				if (sourceFile.Length > 0)
					await destFile.SetLengthAsync(sourceFile.Length, cancellationToken).ConfigureAwait(false);

				using (var sourceStream = sourceFile.GetStream(false))
				using (var destStream = destFile.GetStream(false))
				{
					await sourceStream.CopyToAsync2(destStream, this.ChunkSize, cancellationToken).ConfigureAwait(false);
				}

				if (sourceBasicInfo != null)
				{
					await destFile.SetBasicInfoAsync(
						sourceBasicInfo.CreationTime,
						sourceBasicInfo.LastAccessTime,
						sourceBasicInfo.LastWriteTime,
						sourceBasicInfo.ChangeTime,
						sourceBasicInfo.Attributes,
						cancellationToken).ConfigureAwait(false);
				}
			}
			finally
			{
				if (destFile != null)
					await destFile.CloseAsync(cancellationToken).ConfigureAwait(false);
				if (sourceFile != null)
					await sourceFile.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}

		private static Smb2CreateDisposition GetCreateDisposition(bool destExists, bool preserveSecurityDescriptor)
		{
			if (!destExists)
				return Smb2CreateDisposition.Create;

			return preserveSecurityDescriptor
				? Smb2CreateDisposition.Supersede
				: Smb2CreateDisposition.OverwriteIf;
		}

		private static Smb2CreateInfo CreateAttributeQuery()
		{
			return new Smb2CreateInfo
			{
				OplockLevel = Smb2OplockLevel.None,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				DesiredAccess = (uint)Smb2AccessRights.ReadAttributes,
				FileAttributes = 0,
				ShareAccess = Smb2ShareAccess.ReadWriteDelete,
				CreateDisposition = Smb2CreateDisposition.Open,
				CreateOptions = Smb2FileCreateOptions.OpenReparsePoint | Smb2FileCreateOptions.SynchronousIoNonalert,
				RequestMaximalAccess = true,
				QueryOnDiskId = true
			};
		}

		private static async Task<(UncPath Path, bool Exists)> ResolveDestinationAsync(
			Smb2Client client,
			UncPath sourcePath,
			UncPath destinationPath,
			CancellationToken cancellationToken)
		{
			var destInfo = await TryGetEntryInfoAsync(client, destinationPath, cancellationToken).ConfigureAwait(false);
			bool exists = destInfo.Exists;
			bool isDir = destInfo.IsDir;

			if (isDir)
			{
				string fileName = Path.GetFileName(sourcePath.ShareRelativePath ?? string.Empty);
				if (string.IsNullOrEmpty(fileName))
					throw new IOException($"Source path '{sourcePath}' does not specify a file name.");

				destinationPath = destinationPath.Append(fileName);
				exists = false;

				var fileInfo = await TryGetEntryInfoAsync(client, destinationPath, cancellationToken).ConfigureAwait(false);
				if (fileInfo.Exists && fileInfo.IsDir)
					throw new IOException($"Destination path '{destinationPath}' is a directory.");

				exists = fileInfo.Exists;
			}

			return (destinationPath, exists);
		}

		private static async Task<(bool Exists, bool IsDir)> TryGetEntryInfoAsync(
			Smb2Client client,
			UncPath path,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var openInfo = CreateAttributeQuery();
				file = await client.CreateFileAsync(path, openInfo, FileAccess.Read, cancellationToken).ConfigureAwait(false);
				return (true, file.IsDirectory);
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch
			{
				return (false, false);
			}
			finally
			{
				if (file != null)
					await file.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}
	}
}
