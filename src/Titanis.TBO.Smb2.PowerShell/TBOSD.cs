using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public static class TBOSD
	{
		public static SecurityDescriptor FromRegistryBinary(byte[] value)
			=> SecurityDescriptorHelpers.FromRegistryBinary(value);

		public static SecurityDescriptor FromRegistryBase64(string base64)
			=> SecurityDescriptorHelpers.FromRegistryBase64(base64);

		public static byte[] ToRegistryBinary(SecurityDescriptor descriptor)
			=> SecurityDescriptorHelpers.ToRegistryBinary(descriptor);

		public static string ToRegistryBase64(SecurityDescriptor descriptor)
			=> SecurityDescriptorHelpers.ToRegistryBase64(descriptor);
	}
}
