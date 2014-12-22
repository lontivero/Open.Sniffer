using System;
using System.Net;
using System.Net.Sockets;

namespace Open.Sniffer
{
    public class SnifferBase
    {
        private readonly Socket _socket;

        public SnifferBase(IPAddress bindTo)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            _socket .Bind(new IPEndPoint(bindTo, 0));
            _socket .SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);                           //option to true

            var byTrue = new byte[] {0x1, 0x0, 0x0, 0x0};
            var byOut = new byte[] {0x1, 0x0, 0x0, 0x0};

            _socket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
        }

        public void Start()
        {
            Receive();
        }

        private void Receive()
        {
            var header = new byte[32 * 1024];
            _socket.BeginReceive(header, 0, 32 * 1024, SocketFlags.None, OnReceive, header);
        }

        private void OnReceive(IAsyncResult ar)
        {
            var received = _socket.EndReceive(ar);
            var buffer = new ArraySegment<byte>(ar.AsyncState as byte[], 0, 32*1024);
            var ipHeader = new IPHeader(buffer);
            var packet = ParseData(ipHeader);

            ProcessPacket(ipHeader.ProtocolType, packet);

            var header = new byte[32 * 1024];
            _socket.BeginReceive(header, 0, 32 * 1024, SocketFlags.None, OnReceive, header);
        }

        protected virtual void ProcessPacket(ProtocolType protocolType, object packet)
        {
        }

        private object ParseData(IPHeader ipHeader)
        {
            switch (ipHeader.ProtocolType)
            {
                case ProtocolType.Tcp:
                    return new TcpHeader(ipHeader);

                case ProtocolType.Udp:
                    return new UdpHeader(ipHeader);

                case ProtocolType.Unknown:
                    return null;
            }
            throw new NotSupportedException();
        }
    }
}