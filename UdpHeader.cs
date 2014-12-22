using System.Net;
using System;
using System.IO;

namespace Open.Sniffer
{
    public class UdpHeader
    {
        public short Checksum { get; private set; }
        public ushort SourcePort { get; private set; }
        public ushort DestinationPort { get; private set; }
        public ushort Length { get; private set; }
        public ArraySegment<byte> Data { get; private set; }
        public IPHeader IpHeader { get; private set; }

        public UdpHeader(IPHeader ipHeader)
        {
            IpHeader = ipHeader;
            var buffer = IpHeader.Data;
            using(var memoryStream = new MemoryStream(buffer.Array, buffer.Offset, buffer.Count))
            {
                using (var binaryReader = new BinaryReader(memoryStream))
                {
                    SourcePort = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    DestinationPort = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    Length = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    Checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                }
            }
            Data = new ArraySegment<byte>(buffer.Array, buffer.Offset + 8, buffer.Count - 8);
        }
    }
}