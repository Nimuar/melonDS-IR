#include "IRMDNS.h"

#include <QByteArray>
#include <QHostAddress>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QString>
#include <QStringList>
#include <QUdpSocket>
#include <QVariant>

#include <cstdio>

namespace melonDS::Platform
{

namespace
{

constexpr const char* kMdnsMulticastAddr = "224.0.0.251";
constexpr quint16 kMdnsPort = 5353;
constexpr uint32_t kMdnsTtlSeconds = 120;

constexpr uint16_t kDnsTypeA = 1;
constexpr uint16_t kDnsTypePTR = 12;
constexpr uint16_t kDnsTypeTXT = 16;
constexpr uint16_t kDnsTypeSRV = 33;
constexpr uint16_t kDnsTypeANY = 255;

constexpr uint16_t kDnsClassIN = 1;
constexpr uint16_t kDnsClassFlush = 0x8001;

const QString kServiceType = QStringLiteral("_pixelwalker._tcp.local");
const QString kInstanceName = QStringLiteral("melonDS-IR._pixelwalker._tcp.local");
const QString kHostName = QStringLiteral("melonds-ir.local");
const QString kDnsSdMeta = QStringLiteral("_services._dns-sd._udp.local");

QUdpSocket* g_mdnsSocket = nullptr;
uint16_t g_servicePort = 8081;

void appendU16(QByteArray& out, uint16_t v)
{
    out.append(static_cast<char>((v >> 8) & 0xFF));
    out.append(static_cast<char>(v & 0xFF));
}

void appendU32(QByteArray& out, uint32_t v)
{
    out.append(static_cast<char>((v >> 24) & 0xFF));
    out.append(static_cast<char>((v >> 16) & 0xFF));
    out.append(static_cast<char>((v >> 8) & 0xFF));
    out.append(static_cast<char>(v & 0xFF));
}

uint16_t readU16(const QByteArray& pkt, int offset)
{
    return (static_cast<uint16_t>(static_cast<uint8_t>(pkt[offset])) << 8) |
           static_cast<uint16_t>(static_cast<uint8_t>(pkt[offset + 1]));
}

void appendDnsName(QByteArray& out, const QString& fqdn)
{
    const QStringList parts = fqdn.split('.', Qt::SkipEmptyParts);
    for (const QString& part : parts)
    {
        const QByteArray utf8 = part.toUtf8();
        if (utf8.isEmpty() || utf8.size() > 63)
            continue;
        out.append(static_cast<char>(utf8.size()));
        out.append(utf8);
    }
    out.append('\0');
}

bool readDnsName(const QByteArray& pkt, int& offset, QString& outName)
{
    QStringList labels;
    int pos = offset;
    bool jumped = false;
    int steps = 0;

    while (pos < pkt.size() && steps < 128)
    {
        ++steps;
        const uint8_t len = static_cast<uint8_t>(pkt[pos]);
        if (len == 0)
        {
            if (!jumped)
                offset = pos + 1;
            outName = labels.join('.');
            return true;
        }
        if ((len & 0xC0) == 0xC0)
        {
            if (pos + 1 >= pkt.size())
                return false;
            const int ptr = ((len & 0x3F) << 8) | static_cast<uint8_t>(pkt[pos + 1]);
            if (ptr >= pkt.size())
                return false;
            if (!jumped)
                offset = pos + 2;
            jumped = true;
            pos = ptr;
            continue;
        }
        if ((len & 0xC0) != 0)
            return false;

        if (pos + 1 + len > pkt.size())
            return false;
        labels.append(QString::fromUtf8(pkt.constData() + pos + 1, len));
        pos += 1 + len;
    }
    return false;
}

bool isVirtualInterfaceName(const QString& name)
{
    const QString lower = name.toLower();
    return lower.contains("vethernet") || lower.contains("wsl") ||
           lower.contains("virtualbox") || lower.contains("vbox") ||
           lower.contains("vmware") || lower.contains("docker") ||
           lower.contains("tailscale") || lower.contains("zerotier") ||
           lower.contains("loopback");
}

QHostAddress pickLanIpv4(const QHostAddress& peer = QHostAddress())
{
    QHostAddress bestSameSubnet;
    QHostAddress bestPhysical;
    QHostAddress bestFallback;

    const bool hasPeerV4 = (peer.protocol() == QAbstractSocket::IPv4Protocol);

    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces())
    {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) ||
            !(flags & QNetworkInterface::IsRunning) ||
            (flags & QNetworkInterface::IsLoopBack))
        {
            continue;
        }

        const bool isVirtual = isVirtualInterfaceName(iface.humanReadableName()) ||
                               isVirtualInterfaceName(iface.name());

        for (const QNetworkAddressEntry& entry : iface.addressEntries())
        {
            const QHostAddress ip = entry.ip();
            if (ip.protocol() != QAbstractSocket::IPv4Protocol ||
                ip.isLoopback() || ip.isLinkLocal())
            {
                continue;
            }

            if (hasPeerV4 && !entry.netmask().isNull())
            {
                const quint32 mask = entry.netmask().toIPv4Address();
                if ((ip.toIPv4Address() & mask) == (peer.toIPv4Address() & mask))
                {
                    if (!isVirtual)
                        return ip;
                    if (bestSameSubnet.isNull())
                        bestSameSubnet = ip;
                }
            }

            if (!isVirtual && bestPhysical.isNull())
                bestPhysical = ip;
            if (bestFallback.isNull())
                bestFallback = ip;
        }
    }

    if (!bestSameSubnet.isNull())
        return bestSameSubnet;
    if (!bestPhysical.isNull())
        return bestPhysical;
    return bestFallback;
}

void appendRecord(QByteArray& out, const QString& name, uint16_t type, uint16_t dnsClass,
                  uint32_t ttl, const QByteArray& rdata)
{
    appendDnsName(out, name);
    appendU16(out, type);
    appendU16(out, dnsClass);
    appendU32(out, ttl);
    appendU16(out, static_cast<uint16_t>(rdata.size()));
    out.append(rdata);
}

void appendPtrRecord(QByteArray& out, const QString& owner, const QString& target)
{
    QByteArray rdata;
    appendDnsName(rdata, target);
    appendRecord(out, owner, kDnsTypePTR, kDnsClassIN, kMdnsTtlSeconds, rdata);
}

void appendSrvRecord(QByteArray& out, uint16_t port)
{
    QByteArray rdata;
    appendU16(rdata, 0);    // priority
    appendU16(rdata, 0);    // weight
    appendU16(rdata, port); // port
    appendDnsName(rdata, kHostName);
    appendRecord(out, kInstanceName, kDnsTypeSRV, kDnsClassFlush, kMdnsTtlSeconds, rdata);
}

void appendTxtRecord(QByteArray& out)
{
    QByteArray rdata;
    const QByteArray kv = QByteArrayLiteral("version=1");
    rdata.append(static_cast<char>(kv.size()));
    rdata.append(kv);
    appendRecord(out, kInstanceName, kDnsTypeTXT, kDnsClassFlush, kMdnsTtlSeconds, rdata);
}

void appendARecord(QByteArray& out, const QHostAddress& ipv4)
{
    QByteArray rdata;
    appendU32(rdata, ipv4.toIPv4Address());
    appendRecord(out, kHostName, kDnsTypeA, kDnsClassFlush, kMdnsTtlSeconds, rdata);
}

QByteArray buildMdnsResponsePacket(const QByteArray& answers, uint16_t answerCount,
                                   const QByteArray& additionals, uint16_t additionalCount)
{
    QByteArray pkt;
    pkt.reserve(12 + answers.size() + additionals.size());
    appendU16(pkt, 0x0000); // ID = 0 for mDNS
    appendU16(pkt, 0x8400); // QR=1, AA=1
    appendU16(pkt, 0);      // QDCOUNT
    appendU16(pkt, answerCount);
    appendU16(pkt, 0);      // NSCOUNT
    appendU16(pkt, additionalCount);
    pkt.append(answers);
    pkt.append(additionals);
    return pkt;
}

void sendMdnsAnnouncement()
{
    if (!g_mdnsSocket)
        return;

    const QHostAddress ip = pickLanIpv4();
    if (ip.isNull())
        return;

    QByteArray answers;
    appendPtrRecord(answers, kServiceType, kInstanceName);
    appendSrvRecord(answers, g_servicePort);
    appendTxtRecord(answers);
    appendARecord(answers, ip);

    const QByteArray pkt = buildMdnsResponsePacket(answers, 4, QByteArray(), 0);
    g_mdnsSocket->writeDatagram(pkt, QHostAddress(kMdnsMulticastAddr), kMdnsPort);
    printf("mDNS: announced %s -> %s (%s:%u)\n",
           kInstanceName.toUtf8().constData(),
           kHostName.toUtf8().constData(),
           ip.toString().toUtf8().constData(),
           g_servicePort);
}

void handleMdnsQuery(const QByteArray& datagram, const QHostAddress& sender, quint16 senderPort)
{
    if (datagram.size() < 12)
        return;

    const uint16_t flags = readU16(datagram, 2);
    if ((flags & 0x8000) != 0)
        return; // Ignore responses

    const uint16_t qdCount = readU16(datagram, 4);
    if (qdCount == 0)
        return;

    bool wantMetaPtr = false;
    bool wantPtr = false;
    bool wantSrv = false;
    bool wantTxt = false;
    bool wantA = false;
    bool unicastReply = false;

    int offset = 12;
    for (uint16_t i = 0; i < qdCount; ++i)
    {
        QString qname;
        if (!readDnsName(datagram, offset, qname))
            return;
        if (offset + 4 > datagram.size())
            return;

        const uint16_t qtype = readU16(datagram, offset);
        const uint16_t qclass = readU16(datagram, offset + 2);
        offset += 4;

        const bool qu = (qclass & 0x8000) != 0;
        const uint16_t baseClass = qclass & 0x7FFF;
        if (baseClass != kDnsClassIN && baseClass != kDnsTypeANY)
            continue;

        const QString lower = qname.toLower();
        if (lower == kDnsSdMeta && (qtype == kDnsTypePTR || qtype == kDnsTypeANY))
        {
            wantMetaPtr = true;
            unicastReply = unicastReply || qu;
        }
        else if (lower == kServiceType.toLower() && (qtype == kDnsTypePTR || qtype == kDnsTypeANY))
        {
            wantPtr = true;
            unicastReply = unicastReply || qu;
        }
        else if (lower == kInstanceName.toLower())
        {
            if (qtype == kDnsTypeSRV || qtype == kDnsTypeANY)
                wantSrv = true;
            if (qtype == kDnsTypeTXT || qtype == kDnsTypeANY)
                wantTxt = true;
            if (wantSrv || wantTxt)
                unicastReply = unicastReply || qu;
        }
        else if (lower == kHostName.toLower() && (qtype == kDnsTypeA || qtype == kDnsTypeANY))
        {
            wantA = true;
            unicastReply = unicastReply || qu;
        }
    }

    if (!wantMetaPtr && !wantPtr && !wantSrv && !wantTxt && !wantA)
        return;

    const QHostAddress ip = pickLanIpv4(sender);
    if (ip.isNull())
        return;

    QByteArray answers;
    uint16_t answerCount = 0;
    QByteArray additionals;
    uint16_t additionalCount = 0;

    bool addedSrv = false;
    bool addedTxt = false;
    bool addedA = false;

    if (wantMetaPtr)
    {
        appendPtrRecord(answers, kDnsSdMeta, kServiceType);
        ++answerCount;
    }
    if (wantPtr)
    {
        appendPtrRecord(answers, kServiceType, kInstanceName);
        ++answerCount;
    }
    if (wantSrv)
    {
        appendSrvRecord(answers, g_servicePort);
        ++answerCount;
        addedSrv = true;
    }
    if (wantTxt)
    {
        appendTxtRecord(answers);
        ++answerCount;
        addedTxt = true;
    }
    if (wantA)
    {
        appendARecord(answers, ip);
        ++answerCount;
        addedA = true;
    }

    // Include SRV/TXT/A in Additional section per RFC 6763 §12
    if (wantPtr)
    {
        if (!addedSrv)
        {
            appendSrvRecord(additionals, g_servicePort);
            ++additionalCount;
            addedSrv = true;
        }
        if (!addedTxt)
        {
            appendTxtRecord(additionals);
            ++additionalCount;
            addedTxt = true;
        }
    }
    if ((wantPtr || wantSrv) && !addedA)
    {
        appendARecord(additionals, ip);
        ++additionalCount;
    }

    const QByteArray pkt = buildMdnsResponsePacket(answers, answerCount, additionals, additionalCount);
    if (unicastReply && !sender.isNull() && senderPort != 0)
        g_mdnsSocket->writeDatagram(pkt, sender, senderPort);
    else
        g_mdnsSocket->writeDatagram(pkt, QHostAddress(kMdnsMulticastAddr), kMdnsPort);
}

} // namespace

void IR_StartMDNS(uint16_t port)
{
    g_servicePort = port;
    if (g_mdnsSocket)
        return;

    g_mdnsSocket = new QUdpSocket();
    if (!g_mdnsSocket->bind(QHostAddress::AnyIPv4, kMdnsPort,
                            QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint))
    {
        printf("mDNS: failed to bind UDP 5353: %s\n",
               g_mdnsSocket->errorString().toUtf8().constData());
        delete g_mdnsSocket;
        g_mdnsSocket = nullptr;
        return;
    }

    g_mdnsSocket->setSocketOption(QAbstractSocket::MulticastTtlOption, 255);
    g_mdnsSocket->setSocketOption(QAbstractSocket::MulticastLoopbackOption, 1);

    const QHostAddress mcastGroup(kMdnsMulticastAddr);
    bool joinedAny = false;
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces())
    {
        const auto flags = iface.flags();
        if ((flags & QNetworkInterface::IsUp) &&
            (flags & QNetworkInterface::IsRunning) &&
            (flags & QNetworkInterface::CanMulticast) &&
            !(flags & QNetworkInterface::IsLoopBack))
        {
            if (g_mdnsSocket->joinMulticastGroup(mcastGroup, iface))
                joinedAny = true;
        }
    }
    if (!joinedAny)
        g_mdnsSocket->joinMulticastGroup(mcastGroup);

    QObject::connect(g_mdnsSocket, &QUdpSocket::readyRead, []() {
        IR_PollMDNS();
    });

    sendMdnsAnnouncement();
}

void IR_StopMDNS()
{
    if (!g_mdnsSocket)
        return;

    g_mdnsSocket->close();
    g_mdnsSocket->deleteLater();
    g_mdnsSocket = nullptr;
}

void IR_PollMDNS()
{
    if (!g_mdnsSocket)
        return;

    while (g_mdnsSocket->hasPendingDatagrams())
    {
        QByteArray datagram;
        datagram.resize(static_cast<int>(g_mdnsSocket->pendingDatagramSize()));
        QHostAddress sender;
        quint16 senderPort = 0;
        const qint64 n = g_mdnsSocket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        if (n > 0)
        {
            datagram.resize(static_cast<int>(n));
            handleMdnsQuery(datagram, sender, senderPort);
        }
    }
}

} // namespace melonDS::Platform
