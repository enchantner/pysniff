//
// Created by Nikolay Markov, 2012
//

#include <Python.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
#include <sys/ioctl.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define IFACE "eth0"
#define MTU 1500
#define IP_DF 0x4000
#define IP_MF 0x2000

static PyObject* pysniff_unpack_data(char data[MTU]) {
  struct ethhdr eth;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;
  memcpy((char *) &eth, data, sizeof(struct ethhdr));

  PyObject *packet;
  packet = PyDict_New();
  if (!packet)
    return NULL;

  if (ntohs(eth.h_proto) == ETH_P_IP) {
      ip = (struct iphdr *)(data + sizeof(struct ethhdr));
      PyDict_SetItemString(packet, "ip_source", PyString_FromFormat("%s", inet_ntoa(ip->saddr)));
      PyDict_SetItemString(packet, "ip_destination", PyString_FromFormat("%s", inet_ntoa(ip->daddr)));

      if ((ip->protocol) == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        PyDict_SetItemString(packet, "tcp_source_port", PyString_FromFormat("%d", ntohs(tcp->source)));
        PyDict_SetItemString(packet, "tcp_dest_port", PyString_FromFormat("%d", ntohs(tcp->dest)));
        PyDict_SetItemString(packet, "tcp_seq", PyString_FromFormat("%d", ntohs(tcp->ack_seq)));
        PyDict_SetItemString(packet, "tcp_offset", PyString_FromFormat("%d", tcp->doff));
      }

      if ((ip->protocol) == IPPROTO_UDP) {  
        udp = (struct udphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        PyDict_SetItemString(packet, "udp_source_port", PyString_FromFormat("%d", ntohs(udp->source)));
        PyDict_SetItemString(packet, "udp_dest_port", PyString_FromFormat("%d", ntohs(udp->source)));
        PyDict_SetItemString(packet, "udp_length", PyString_FromFormat("%d", ntohs(udp->len)));
      }
  }

  return packet;
}

typedef struct {
    PyObject_HEAD
    int s_sock;
} PacketGeneratorState;

static PyObject *
packgen_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    int s_sock;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, IFACE);
    if ( (s_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Error creating socket");
        exit(-1);
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(s_sock, SIOCGIFFLAGS, &ifr) < 0) {
      perror("Unable to set promiscious mode for device");
      close(s_sock);
      exit(-1);
    }

    PacketGeneratorState *pkstate = (PacketGeneratorState *)type->tp_alloc(type, 0);
    if (!pkstate)
        return NULL;

    pkstate->s_sock = s_sock;

    return (PyObject *)pkstate;
}

static void
packgen_dealloc(PacketGeneratorState *pkstate)
{
    Py_TYPE(pkstate)->tp_free(pkstate);
}

static PyObject *
packgen_next(PacketGeneratorState *pkstate)
{
    int n = 0;
    char buf[MTU];

    n = recvfrom(pkstate->s_sock, buf, sizeof(buf), 0, 0, 0);
    if (!n) 
      return NULL;

    PyObject *result = Py_BuildValue("O", pysniff_unpack_data(buf));
    return result;
}

PyTypeObject PyPacketGenerator_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "packgen",                       /* tp_name */
    sizeof(PacketGeneratorState),            /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)packgen_dealloc,     /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_reserved */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    0,                              /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    PyObject_SelfIter,              /* tp_iter */
    (iternextfunc)packgen_next,      /* tp_iternext */
    0,                              /* tp_methods */
    0,                              /* tp_members */
    0,                              /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    0,                              /* tp_init */
    PyType_GenericAlloc,            /* tp_alloc */
    packgen_new,                     /* tp_new */
};

static PyMethodDef SniffMethods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initpysniff(void)
{
    PyObject *m;

    m = Py_InitModule("pysniff", SniffMethods);
    if (m == NULL)
        return;

    if (PyType_Ready(&PyPacketGenerator_Type) < 0)
        return;
    Py_INCREF((PyObject *)&PyPacketGenerator_Type);
    PyModule_AddObject(m, "packgen", (PyObject *)&PyPacketGenerator_Type);
}