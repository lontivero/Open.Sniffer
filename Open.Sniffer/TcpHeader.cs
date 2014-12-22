using System.Net;
using System;
using System.IO;

namespace Open.Sniffer
{
    [Flags]
    public enum TcpFlags
    {
        Fin = 1,
        Syn = 2,
        Rst = 4,
        Psh = 8,
        Ack = 16,
        Urg = 32
    }

    public class TcpHeader
    {
        private readonly uint   _uiAcknowledgementNumber=555;
        private readonly ushort _usDataOffsetAndFlags=555;
        private readonly ushort _usUrgentPointer;

        public ushort SourcePort { get; private set; }
        public ushort DestinationPort { get; private set; }
        public ushort WindowSize { get; private set; }

        public uint SequenceNumber { get; private set; }
        public byte HeaderLength { get; private set; }
        public short Checksum { get; private set; }
        public ArraySegment<byte> Data { get; private set; }
        public int MessageLength { get; private set; }

        public IPHeader IpHeader { get; private set; }

        public TcpHeader(IPHeader ipHeader)
        {
            IpHeader = ipHeader;
            var buffer = IpHeader.Data;
            using (var memoryStream = new MemoryStream(buffer.Array, buffer.Offset, buffer.Count))
            {
                using (var binaryReader = new BinaryReader(memoryStream))
                {
                    SourcePort = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    DestinationPort = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    SequenceNumber = (uint) IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());
                    _uiAcknowledgementNumber = (uint) IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());
                    _usDataOffsetAndFlags = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    WindowSize = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    Checksum = (short) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    _usUrgentPointer = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    HeaderLength = (byte) (_usDataOffsetAndFlags >> 12);
                    HeaderLength *= 4;
                    MessageLength = buffer.Count - HeaderLength;
                }
            }
            Data = new ArraySegment<byte>(buffer.Array, buffer.Offset + HeaderLength, MessageLength);
        }

        public string AcknowledgementNumber
        {
            get
            {
                return Flags.HasFlag(TcpFlags.Ack) ? _uiAcknowledgementNumber.ToString() : "";
            }
        }


        public string UrgentPointer
        {
            get
            {
                return Flags.HasFlag(TcpFlags.Urg) ? _usUrgentPointer.ToString() : "";
            }
        }

        public TcpFlags Flags
        {
            get
            {
                int flags = _usDataOffsetAndFlags & 0x3F;
                return (TcpFlags) flags;
            }
        }
    }
}