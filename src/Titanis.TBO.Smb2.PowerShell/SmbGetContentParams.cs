using Microsoft.PowerShell.Commands;
using System.Management.Automation;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal class SmbGetContentParams:FileSystemContentReaderDynamicParameters
	{
		const string TypeSetName = "Type";

		[Parameter(ParameterSetName = TypeSetName)]
		public new SwitchParameter Raw { get; set; }
	}
}
