using System;
using System.IO;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProvider
	{
		protected override void RemoveItem(string path, bool recurse)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			UncPath uncPath = UncPath.Parse(path);
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new ArgumentException("Path must include a file or directory name.", nameof(path));

			this.BeginOperation(cancellationToken =>
			{
				RemoveItemCore(uncPath, recurse, cancellationToken);
			});
		}

		private void RemoveItemCore(UncPath uncPath, bool recurse, System.Threading.CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				file = this.smb.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.ReadAttributes,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					FileAttributes = Winterop.FileAttributes.Normal,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenReparsePoint
						| Smb2FileCreateOptions.OpenForBackupIntent,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation
				}, FileAccess.Read, cancellationToken).Result;

				if (!file.IsDirectory)
				{
					this.smb.SmbClient.DeleteFileAsync(uncPath, cancellationToken).GetAwaiter().GetResult();
					return;
				}
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}

			if (recurse)
			{
				RemoveDirectoryRecursive(uncPath, cancellationToken);
				return;
			}

			this.smb.SmbClient.RemoveDirectoryAsync(uncPath, cancellationToken).GetAwaiter().GetResult();
		}

		private void RemoveDirectoryRecursive(UncPath directoryPath, System.Threading.CancellationToken cancellationToken)
		{
			Smb2Directory? dir = null;
			try
			{
				dir = (Smb2Directory)this.smb.SmbClient.CreateFileAsync(directoryPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					Priority = Smb2Priority.OpenDir,
					DesiredAccess = (uint)Smb2AccessRights.DefaultOpenDirAccess,
					ShareAccess = Smb2ShareAccess.DefaultDirShare,
					FileAttributes = Winterop.FileAttributes.None,
					CreateOptions = Smb2FileCreateOptions.Directory
						| Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenReparsePoint
						| Smb2FileCreateOptions.OpenForBackupIntent,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					RequestMaximalAccess = true,
					QueryOnDiskId = true,
					OplockLevel = Smb2OplockLevel.None
				}, FileAccess.Read, cancellationToken).Result;

				foreach (var entry in dir.QueryDirAsync("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken).Result)
				{
					if (entry.FileName is "." or "..")
						continue;

					var childPath = directoryPath.Append(entry.FileName);
					bool isDirectory = 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory);
					bool isReparse = 0 != (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint);

					if (isDirectory && !isReparse)
					{
						RemoveDirectoryRecursive(childPath, cancellationToken);
						continue;
					}

					if (isDirectory)
						this.smb.SmbClient.RemoveDirectoryAsync(childPath, cancellationToken).GetAwaiter().GetResult();
					else
						this.smb.SmbClient.DeleteFileAsync(childPath, cancellationToken).GetAwaiter().GetResult();
				}
			}
			finally
			{
				if (dir != null)
					dir.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}

			this.smb.SmbClient.RemoveDirectoryAsync(directoryPath, cancellationToken).GetAwaiter().GetResult();
		}
	}
}
