using System.Diagnostics;
using System.Net;
using System;
using System.IO;
using System.Net.Sockets;

namespace Open.Sniffer
{
    public enum IPVersion
    {
        None = 0,
        IPv4 = 1,
        IPv6 = 2
    }

    public enum IPFlag
    {
        Reserved = 0,
        DontFragment = 1,
        MoreFragments=2
    }

    public class IPHeader
    {
        //IP Header fields
        private readonly ushort    _flagsAndOffset;          
        private readonly byte      _protocol;

        public ArraySegment<byte> Raw { get; protected set; }
        public ArraySegment<byte> Data { get; protected set; }

        public int HeaderLength { get; private set; }
        public byte Ttl { get; private set; }
        public byte DifferentiatedServices { get; private set; }
        public byte CongestionNotification { get; private set; }

        public short Checksum { get; private set; }
        public ushort TotalLength { get; private set; }
        public ushort Identification { get; private set; }
        public IPAddress SourceAddress { get; private set; }
        public IPAddress DestinationAddress { get; private set; }

        public IPHeader(ArraySegment<byte> buffer)
        {

            using (var memoryStream = new MemoryStream(buffer.Array, buffer.Offset, buffer.Count))
            {
                using (var binaryReader = new BinaryReader(memoryStream))
                {
                    var versionAndHeaderLength = binaryReader.ReadByte();
                    var differentiatedServices = binaryReader.ReadByte();

                    DifferentiatedServices = (byte)(differentiatedServices >> 2);
                    CongestionNotification = (byte)(differentiatedServices & 0x03);

                    TotalLength = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                    Debug.Assert(TotalLength >= 20, "Invalid IP packet Total Lenght");
                    Identification = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    _flagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    Ttl = binaryReader.ReadByte();

                    _protocol = binaryReader.ReadByte();

                    Checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    SourceAddress = new IPAddress(binaryReader.ReadUInt32());
                    DestinationAddress = new IPAddress(binaryReader.ReadUInt32());

                    HeaderLength = (versionAndHeaderLength & 0x0f) * 4;
                }
            }

            Raw = buffer;
            Data = new ArraySegment<byte>(buffer.Array, buffer.Offset + HeaderLength, MessageLength);
        }


        public IPVersion Version
        {
            get
            {
                var ver = HeaderLength >> 4;
                if (ver == 4) return IPVersion.IPv4;
                if (ver == 6) return IPVersion.IPv6;
                return IPVersion.None;
            }
        }

        public ProtocolType ProtocolType
        {
            get
            {
                if (_protocol == 6) return ProtocolType.Tcp;
                if (_protocol == 17) return ProtocolType.Udp;
                return ProtocolType.Unknown;
            }
        }

        public int MessageLength
        {
            get { return TotalLength - HeaderLength; }
        }

        public IPFlag Flags
        {
            get { return (IPFlag)(_flagsAndOffset >> 13); }
        }

        public int FragmentationOffset
        {
            get { return (_flagsAndOffset << 3) >> 3; }
        }

        public bool IsFragment
        {
            get { return Flags == IPFlag.MoreFragments || FragmentationOffset > 0; }
        }
    }
}
