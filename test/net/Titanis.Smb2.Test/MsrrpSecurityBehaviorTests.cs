using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ms_dtyp;
using ms_rrp;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.IO;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Smb2.Test
{
	[TestClass]
	public class MsrrpSecurityBehaviorTests
	{
		[TestMethod]
		public async Task QuerySecurity_RetriesWithFullBufferAfterInvalidParameter()
		{
			byte[] expectedDescriptor = { 0x01, 0x02, 0x03, 0x04 };

			var proxy = new RecordingWinregProxy
			{
				QueryInfoResultCode = Win32ErrorCode.ERROR_ACCESS_DENIED,
				OnGetKeySecurity = (callIndex, request) => callIndex switch
				{
					1 => new GetSecurityResponse(Win32ErrorCode.ERROR_INVALID_PARAMETER, Array.Empty<byte>(), 0),
					2 => new GetSecurityResponse(Win32ErrorCode.ERROR_SUCCESS, expectedDescriptor),
					_ => throw new InvalidOperationException("Unexpected BaseRegGetKeySecurity invocation.")
				}
			};

			var key = CreateRegistryKey(proxy);
			var actual = await key.QuerySecurity(SecurityInfo.Dacl, CancellationToken.None).ConfigureAwait(false);

			CollectionAssert.AreEqual(expectedDescriptor, actual);
			Assert.AreEqual(1, proxy.QueryInfoCallCount, "Expected a single QueryInfo attempt before fallback.");
			Assert.AreEqual(2, proxy.GetKeySecurityRequests.Count, "Expected initial call + fallback retry.");

			var firstCall = proxy.GetKeySecurityRequests[0];
			var secondCall = proxy.GetKeySecurityRequests[1];

			Assert.AreEqual(0, firstCall.Count, "First request should use a zero-count varying segment.");
			Assert.IsTrue(firstCall.MaxCount >= 8192, "First request should advertise default buffer capacity.");
			Assert.AreEqual(0U, firstCall.CbOut, "First request should not set cbOutSecurityDescriptor.");

			Assert.AreEqual(secondCall.MaxCount, secondCall.Count, "Retry should send the full descriptor buffer.");
			Assert.AreEqual((uint)secondCall.Count, secondCall.CbOut, "Retry should set cbOutSecurityDescriptor to buffer size.");
		}

		[TestMethod]
		public async Task SetSecurity_MarshalsDescriptorLengthToCbInAndCbOut()
		{
			byte[] descriptor = { 0x30, 0x31, 0x32, 0x33, 0x34 };

			var proxy = new RecordingWinregProxy
			{
				OnSetKeySecurity = (_, _) => Win32ErrorCode.ERROR_SUCCESS
			};

			var key = CreateRegistryKey(proxy);
			await key.SetSecurity(SecurityInfo.Dacl, descriptor, CancellationToken.None).ConfigureAwait(false);

			Assert.AreEqual(1, proxy.SetKeySecurityRequests.Count);
			var captured = proxy.SetKeySecurityRequests[0];

			Assert.AreEqual((uint)descriptor.Length, captured.CbIn);
			Assert.AreEqual((uint)descriptor.Length, captured.CbOut);
			Assert.AreEqual(descriptor.Length, captured.Count);
			CollectionAssert.AreEqual(descriptor, captured.Payload);
		}

		[TestMethod]
		public async Task SetSecurity_DoesNotRetryWithBackupFlagOnAccessDenied()
		{
			var proxy = new RecordingWinregProxy
			{
				OnSetKeySecurity = (_, _) => Win32ErrorCode.ERROR_ACCESS_DENIED
			};

			var key = CreateRegistryKey(proxy);
			var ex = await Assert.ThrowsExactlyAsync<Win32Exception>(async () =>
				await key.SetSecurity(SecurityInfo.Dacl, new byte[] { 0x10, 0x20 }, CancellationToken.None).ConfigureAwait(false)
			).ConfigureAwait(false);

			Assert.AreEqual((int)Win32ErrorCode.ERROR_ACCESS_DENIED, ex.NativeErrorCode);
			Assert.AreEqual(1, proxy.SetKeySecurityRequests.Count, "Titanis should not retry SetSecurity with Backup flag.");
			Assert.AreEqual((uint)SecurityInfo.Dacl, proxy.SetKeySecurityRequests[0].SecurityInformation);
		}

		private static RegistryKey CreateRegistryKey(RecordingWinregProxy proxy)
		{
			var owner = new RemoteRegistryClient();
			var proxyField = owner.GetType().BaseType?.GetField("_proxy", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(proxyField, "Could not locate RemoteRegistryClient proxy field.");
			proxyField.SetValue(owner, proxy);

			var ctor = typeof(RegistryKey).GetConstructor(
				BindingFlags.Instance | BindingFlags.NonPublic,
				null,
				new[] { typeof(string), typeof(string), typeof(RpcContextHandle), typeof(RemoteRegistryClient) },
				null);
			Assert.IsNotNull(ctor, "Could not locate non-public RegistryKey constructor.");

			return (RegistryKey)ctor.Invoke(new object[]
			{
				"HKEY_LOCAL_MACHINE",
				"HKEY_LOCAL_MACHINE",
				new RpcContextHandle(),
				owner
			});
		}

		private readonly record struct SecurityDescriptorCall(
			uint SecurityInformation,
			uint CbIn,
			uint CbOut,
			int MaxCount,
			int Offset,
			int Count,
			byte[] Payload);

		private readonly record struct GetSecurityResponse(
			Win32ErrorCode ErrorCode,
			byte[] Payload,
			uint? CbOutSecurityDescriptor = null);

		private sealed class RecordingWinregProxy : winregClientProxy
		{
			private static readonly ConstructorInfo RequestBuilderCtor =
				typeof(RpcRequestBuilder).GetConstructor(
					BindingFlags.Instance | BindingFlags.NonPublic,
					null,
					new[] { typeof(ushort), typeof(RpcEncoding), typeof(RpcCallContext), typeof(bool) },
					null)
				?? throw new InvalidOperationException("Could not locate RpcRequestBuilder constructor.");

			private static readonly FieldInfo RequestOpnumField =
				typeof(RpcRequestBuilder).GetField("_opnum", BindingFlags.Instance | BindingFlags.NonPublic)
				?? throw new InvalidOperationException("Could not locate RpcRequestBuilder _opnum field.");

			private static readonly FieldInfo RequestCallDataOffsetField =
				typeof(RpcRequestBuilder).GetField("_offCallData", BindingFlags.Instance | BindingFlags.NonPublic)
				?? throw new InvalidOperationException("Could not locate RpcRequestBuilder _offCallData field.");

			public int QueryInfoCallCount { get; private set; }
			public List<SecurityDescriptorCall> GetKeySecurityRequests { get; } = new();
			public List<SecurityDescriptorCall> SetKeySecurityRequests { get; } = new();

			public Win32ErrorCode QueryInfoResultCode { get; set; } = Win32ErrorCode.ERROR_SUCCESS;
			public uint QueryInfoSecurityDescriptorLength { get; set; }
			public Func<int, SecurityDescriptorCall, GetSecurityResponse> OnGetKeySecurity { get; set; }
			public Func<int, SecurityDescriptorCall, Win32ErrorCode> OnSetKeySecurity { get; set; }

			protected override RpcRequestBuilder CreateRequest(ushort opnum)
			{
				return (RpcRequestBuilder)RequestBuilderCtor.Invoke(new object[]
				{
					opnum,
					RpcEncoding.MsrpcNdr,
					new RpcCallContext(null),
					false
				});
			}

			protected override Task<RpcDecoder> SendRequestAsync(IRpcRequestBuilder stubData, CancellationToken cancellationToken)
			{
				var request = (RpcRequestBuilder)stubData;
				var opnum = (ushort)RequestOpnumField.GetValue(request);

				RpcDecoder response = opnum switch
				{
					12 => this.HandleGetKeySecurityRequest(request),
					16 => this.HandleQueryInfoRequest(),
					21 => this.HandleSetKeySecurityRequest(request),
					_ => throw new NotSupportedException($"Unexpected opnum in test proxy: {opnum}.")
				};

				return Task.FromResult(response);
			}

			private RpcDecoder HandleQueryInfoRequest()
			{
				this.QueryInfoCallCount++;
				return CreateQueryInfoResponse(this.QueryInfoResultCode, this.QueryInfoSecurityDescriptorLength);
			}

			private RpcDecoder HandleGetKeySecurityRequest(RpcRequestBuilder request)
			{
				var decoder = CreateRequestDecoder(request);
				_ = decoder.ReadContextHandle();
				uint securityInformation = decoder.ReadUInt32();
				var descriptor = decoder.ReadFixedStruct<RPC_SECURITY_DESCRIPTOR>(NdrAlignment.NativePtr);
				decoder.ReadStructDeferral(ref descriptor);

				var captured = CaptureDescriptorCall(securityInformation, descriptor);
				this.GetKeySecurityRequests.Add(captured);

				GetSecurityResponse response = this.OnGetKeySecurity?.Invoke(this.GetKeySecurityRequests.Count, captured)
					?? new GetSecurityResponse(Win32ErrorCode.ERROR_SUCCESS, Array.Empty<byte>());

				uint cbOut = response.CbOutSecurityDescriptor ?? (uint)response.Payload.Length;
				return CreateGetKeySecurityResponse(response.ErrorCode, response.Payload, cbOut);
			}

			private RpcDecoder HandleSetKeySecurityRequest(RpcRequestBuilder request)
			{
				var decoder = CreateRequestDecoder(request);
				_ = decoder.ReadContextHandle();
				uint securityInformation = decoder.ReadUInt32();
				var descriptor = decoder.ReadFixedStruct<RPC_SECURITY_DESCRIPTOR>(NdrAlignment.NativePtr);
				decoder.ReadStructDeferral(ref descriptor);

				var captured = CaptureDescriptorCall(securityInformation, descriptor);
				this.SetKeySecurityRequests.Add(captured);

				var result = this.OnSetKeySecurity?.Invoke(this.SetKeySecurityRequests.Count, captured)
					?? Win32ErrorCode.ERROR_SUCCESS;

				return CreateSetKeySecurityResponse(result);
			}

			private static RpcDecoder CreateRequestDecoder(RpcRequestBuilder request)
			{
				int offset = (int)RequestCallDataOffsetField.GetValue(request);
				ReadOnlyMemory<byte> requestData = request.StubData.GetWriter().GetData().Slice(offset);
				return RpcEncoding.MsrpcNdr.CreateDecoder(new ByteMemoryReader(requestData), new RpcCallContext(null));
			}

			private static SecurityDescriptorCall CaptureDescriptorCall(uint securityInformation, RPC_SECURITY_DESCRIPTOR descriptor)
			{
				if (descriptor.lpSecurityDescriptor == null || descriptor.lpSecurityDescriptor.value.Array == null)
				{
					return new SecurityDescriptorCall(
						securityInformation,
						descriptor.cbInSecurityDescriptor,
						descriptor.cbOutSecurityDescriptor,
						0,
						0,
						0,
						Array.Empty<byte>());
				}

				var segment = descriptor.lpSecurityDescriptor.value;
				byte[] payload = segment.Count == 0 ? Array.Empty<byte>() : segment.AsSpan().ToArray();
				return new SecurityDescriptorCall(
					securityInformation,
					descriptor.cbInSecurityDescriptor,
					descriptor.cbOutSecurityDescriptor,
					segment.Array.Length,
					segment.Offset,
					segment.Count,
					payload);
			}

			private static RpcDecoder CreateQueryInfoResponse(Win32ErrorCode resultCode, uint securityDescriptorLength)
			{
				return CreateResponse(encoder =>
				{
					var classOut = new RPC_UNICODE_STRING();
					encoder.WriteFixedStruct(classOut, NdrAlignment.NativePtr);
					encoder.WriteStructDeferral(classOut);

					encoder.WriteValue(0U);
					encoder.WriteValue(0U);
					encoder.WriteValue(0U);
					encoder.WriteValue(0U);
					encoder.WriteValue(0U);
					encoder.WriteValue(0U);
					encoder.WriteValue(securityDescriptorLength);

					var fileTime = new FILETIME();
					encoder.WriteFixedStruct(fileTime, NdrAlignment._4Byte);
					encoder.WriteStructDeferral(fileTime);
					encoder.WriteValue((int)resultCode);
				});
			}

			private static RpcDecoder CreateGetKeySecurityResponse(Win32ErrorCode resultCode, byte[] payload, uint cbOutSecurityDescriptor)
			{
				return CreateResponse(encoder =>
				{
					byte[] data = payload ?? Array.Empty<byte>();
					var descriptor = new RPC_SECURITY_DESCRIPTOR
					{
						lpSecurityDescriptor = new RpcPointer<ArraySegment<byte>>(new ArraySegment<byte>(data, 0, data.Length)),
						cbInSecurityDescriptor = cbOutSecurityDescriptor,
						cbOutSecurityDescriptor = cbOutSecurityDescriptor
					};

					encoder.WriteFixedStruct(descriptor, NdrAlignment.NativePtr);
					encoder.WriteStructDeferral(descriptor);
					encoder.WriteValue((int)resultCode);
				});
			}

			private static RpcDecoder CreateSetKeySecurityResponse(Win32ErrorCode resultCode)
			{
				return CreateResponse(encoder =>
				{
					encoder.WriteValue((int)resultCode);
				});
			}

			private static RpcDecoder CreateResponse(Action<RpcEncoder> build)
			{
				var writer = new ByteWriter();
				var encoder = RpcEncoding.MsrpcNdr.CreateEncoder(writer, new RpcCallContext(null));
				build(encoder);
				ReadOnlyMemory<byte> data = writer.GetData();
				return RpcEncoding.MsrpcNdr.CreateDecoder(new ByteMemoryReader(data), new RpcCallContext(null));
			}
		}
	}
}
