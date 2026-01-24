using System;
using System.Security.AccessControl;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal enum SecurityDescriptorOutputFormat
	{
		Object,
		Sddl,
		Bytes,
		Windows
	}

	internal static class SecurityDescriptorHelpers
	{
		internal static SecurityDescriptorOutputFormat ResolveFormat(
			bool asSddl,
			bool asBytes,
			bool asWindows)
		{
			int selected = (asSddl ? 1 : 0) + (asBytes ? 1 : 0) + (asWindows ? 1 : 0);
			if (selected > 1)
				throw new ArgumentException("Only one security descriptor output format can be selected.");

			if (asSddl) return SecurityDescriptorOutputFormat.Sddl;
			if (asBytes) return SecurityDescriptorOutputFormat.Bytes;
			if (asWindows) return SecurityDescriptorOutputFormat.Windows;
			return SecurityDescriptorOutputFormat.Object;
		}

		internal static object Format(SecurityDescriptor descriptor, SecurityDescriptorOutputFormat format)
		{
			if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));

			return format switch
			{
				SecurityDescriptorOutputFormat.Sddl => descriptor.ToSddlString(SecurityDescriptorSections.All),
				SecurityDescriptorOutputFormat.Bytes => descriptor.ToByteArray(),
				SecurityDescriptorOutputFormat.Windows => ToWindowsSecurityDescriptor(descriptor),
				_ => descriptor
			};
		}

		internal static SecurityDescriptor FromBytes(byte[] bytes)
		{
			if (bytes is null) throw new ArgumentNullException(nameof(bytes));
			return new SecurityDescriptor(bytes);
		}

		internal static SecurityDescriptor FromSddl(string sddl)
		{
			if (string.IsNullOrWhiteSpace(sddl)) throw new ArgumentException("Value cannot be null or empty.", nameof(sddl));
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");

			var raw = new RawSecurityDescriptor(sddl);
			byte[] buffer = new byte[raw.BinaryLength];
			raw.GetBinaryForm(buffer, 0);
			return new SecurityDescriptor(buffer);
		}

		internal static SecurityDescriptor FromWindowsSecurityDescriptor(RawSecurityDescriptor raw)
		{
			if (raw is null) throw new ArgumentNullException(nameof(raw));
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");

			byte[] buffer = new byte[raw.BinaryLength];
			raw.GetBinaryForm(buffer, 0);
			return new SecurityDescriptor(buffer);
		}

		internal static SecurityDescriptor FromWindowsSecurityDescriptor(CommonSecurityDescriptor descriptor)
		{
			if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");

			byte[] buffer = new byte[descriptor.BinaryLength];
			descriptor.GetBinaryForm(buffer, 0);
			return new SecurityDescriptor(buffer);
		}

		private static RawSecurityDescriptor ToWindowsSecurityDescriptor(SecurityDescriptor descriptor)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");
			byte[] bytes = descriptor.ToByteArray();
			return new RawSecurityDescriptor(bytes, 0);
		}
	}
}
