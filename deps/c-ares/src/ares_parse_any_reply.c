
/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"

int ares_parse_any_reply(const unsigned char *abuf, int alen,
                         struct ares_any_reply ** any_reply)
{
  unsigned int qdcount, ancount, nscount, arcount;
  int status, i, rr_type, rr_class, rr_len, rr_ttl;
  long len;
  const unsigned char *aptr;
  char *hostname, *rr_name, *rr_data;

  struct ares_any_reply *any_reply_local;
  struct ares_any_reply *any_reply_current;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  nscount = DNS_HEADER_NSCOUNT(abuf);
  arcount = DNS_HEADER_ARCOUNT(abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares__expand_name_for_response(aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      free(hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  any_reply_local = ares_malloc_data(ARES_DATATYPE_ANY_REPLY);
  // memset(any_reply_local, 0, sizeof(struct ares_any_reply));
  *any_reply = any_reply_local;
  any_reply_current = any_reply_local;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int)ancount + (int)nscount + (int)arcount; i++)
    {
      if (memcmp(aptr+1, "\x00\x29", 2) == 0) {
        // printf("TYPE OPT (EDNS for example) -> cant parse\n");
        break;
      }

      /* Decode the RR up to the data field. */
      status = ares__expand_name_for_response(aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
        break;
      aptr += len;

      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          free(rr_name);
          break;
        }

      rr_type = DNS_RR_TYPE(aptr);
      rr_class = DNS_RR_CLASS(aptr);
      rr_len = DNS_RR_LEN(aptr);
      rr_ttl = DNS_RR_TTL(aptr);
      aptr += RRFIXEDSZ;

      if (aptr + rr_len > abuf + alen)
        {
          status = ARES_EBADRESP;
          free(rr_name);
          break;
        }

      if (rr_class == C_IN && rr_type == T_A)
        {
          snprintf(any_reply_current->type, 16, "A");
          any_reply_current->name = rr_name;

          any_reply_current->data = malloc(INET_ADDRSTRLEN);
          ares_inet_ntop(AF_INET, aptr, any_reply_current->data, INET_ADDRSTRLEN);
          any_reply_current->length = strlen(any_reply_current->data);

          status = ARES_SUCCESS;
        }

      else if (rr_class == C_IN && rr_type == T_CNAME)
        {
          status = ares__expand_name_for_response(aptr, abuf, alen, &rr_data,
                                                  &len);
          if (status != ARES_SUCCESS)
            break;

          snprintf(any_reply_current->type, 16, "CNAME");
          any_reply_current->name = rr_name;

          any_reply_current->length = strlen(rr_data);
          any_reply_current->data = rr_data;

          status = ARES_SUCCESS;
        }

      else if (rr_class == C_IN && rr_type == T_AAAA)
        {
          snprintf(any_reply_current->type, 16, "AAAA");
          any_reply_current->name = rr_name;

          any_reply_current->data = malloc(INET6_ADDRSTRLEN);
          ares_inet_ntop(AF_INET6, aptr, any_reply_current->data, INET6_ADDRSTRLEN);
          any_reply_current->length = strlen(any_reply_current->data);

          status = ARES_SUCCESS;
        }

      /* Check if we are really looking at a TXT record */
      else if (rr_class == C_IN && rr_type == T_TXT)
        {
          /*
           * There may be multiple substrings in a single TXT record. Each
           * substring may be up to 255 characters in length, with a
           * "length byte" indicating the size of the substring payload.
           * RDATA contains both the length-bytes and payloads of all
           * substrings contained therein.
           */
          const unsigned char *strptr;
          unsigned char *dataptr;

          snprintf(any_reply_current->type, 16, "TXT");
          any_reply_current->name = rr_name;

          any_reply_current->data = malloc(rr_len);
          any_reply_current->length = rr_len;
          memcpy(any_reply_current->data, aptr, rr_len);

          strptr = aptr;
          dataptr = any_reply_current->data;
          while (strptr < (aptr + rr_len))
            {
              size_t substr_len = (unsigned char)*strptr;
              if (strptr + substr_len + 1 > aptr + rr_len)
                {
                  status = ARES_EBADRESP;
                  break;
                }

              *dataptr = '|';
              strptr += substr_len + 1;
              dataptr += substr_len + 1;
            }
        }
      else if (rr_class == C_IN && rr_type == T_SOA)
        {
          const unsigned char *aptr2 = aptr;

          /* allocate result struct */
          struct ares_soa_reply *soa = ares_malloc_data(ARES_DATATYPE_SOA_REPLY);
          if (!soa) {
            status = ARES_ENOMEM;
            break;
          }

          /* nsname */
          status = ares__expand_name_for_response(aptr2, abuf, alen, &soa->nsname, &len);
          if (status != ARES_SUCCESS) {
            ares_free_data(soa);
            status = ARES_EBADRESP;
            break;
          }
          aptr2 += len;

          /* hostmaster */
          status = ares__expand_name_for_response(aptr2, abuf, alen, &soa->hostmaster, &len);
          if (status != ARES_SUCCESS) {
            ares_free_data(soa);
            status = ARES_EBADRESP;
            break;
          }
          aptr2 += len;

          /* integer fields */
          if (aptr2 + 5 * 4 > abuf + alen) {
            ares_free_data(soa);
            status = ARES_EBADRESP;
            break;
          }
          soa->serial = DNS__32BIT(aptr2 + 0 * 4);
          soa->refresh = DNS__32BIT(aptr2 + 1 * 4);
          soa->retry = DNS__32BIT(aptr2 + 2 * 4);
          soa->expire = DNS__32BIT(aptr2 + 3 * 4);
          soa->minttl = DNS__32BIT(aptr2 + 4 * 4);

          snprintf(any_reply_current->type, 16, "SOA");
          any_reply_current->name = rr_name;

          size_t outmaxlen = strlen(soa->nsname) + strlen(soa->hostmaster) + 50 + 7;
          any_reply_current->data = malloc(outmaxlen);
          snprintf(any_reply_current->data, outmaxlen, "%s %s %u %u %u %u %u",
            soa->nsname, soa->hostmaster,
            soa->serial, soa->refresh, soa->retry, soa->expire, soa->minttl
          );
          any_reply_current->length = strlen(any_reply_current->data);

          ares_free_data(soa);
        }

      /* Check if we are really looking at a SRV record */
      else if (rr_class == C_IN && rr_type == T_SRV)
        {
          /* parse the SRV record itself */
          if (rr_len >= 6)
            {
              const unsigned char *aptr2 = aptr;

              /* Allocate storage for this SRV answer appending it to the list */
              struct ares_srv_reply *srv = ares_malloc_data(ARES_DATATYPE_SRV_REPLY);

              srv->priority = DNS__16BIT(aptr2);
              aptr2 += sizeof(unsigned short);
              srv->weight = DNS__16BIT(aptr2);
              aptr2 += sizeof(unsigned short);
              srv->port = DNS__16BIT(aptr2);
              aptr2 += sizeof(unsigned short);

              status = ares_expand_name (aptr2, abuf, alen, &srv->host, &len);
              if (status != ARES_SUCCESS)
                break;

              snprintf(any_reply_current->type, 16, "SRV");
              any_reply_current->name = rr_name;

              size_t outmaxlen = strlen(srv->host) + 2*3 + 5;
              any_reply_current->data = malloc(outmaxlen);
              snprintf(any_reply_current->data, outmaxlen, "%u %u %u %s",
                srv->priority, srv->weight, srv->port, srv->host
              );
              any_reply_current->length = strlen(any_reply_current->data);

              ares_free_data(srv);
            }
        }

      /* Check if we are really looking at a MX record */
      else if (rr_class == C_IN && rr_type == T_MX)
        {
          const unsigned char *aptr2 = aptr;
          unsigned short priority;
          char * mxhost;

          /* parse the MX record itself */
          if (rr_len < 2)
            {
              status = ARES_EBADRESP;
              break;
            }

          priority = DNS__16BIT(aptr2);
          aptr2 += 2;

          status = ares_expand_name (aptr2, abuf, alen, &mxhost, &len);
          if (status != ARES_SUCCESS)
            break;

          snprintf(any_reply_current->type, 16, "MX");
          any_reply_current->name = rr_name;

          any_reply_current->data = malloc(strlen(mxhost) + 5 + 2);
          snprintf(any_reply_current->data, strlen(mxhost) + 5 + 2, "%hu %s", priority, mxhost);
          any_reply_current->length = strlen(any_reply_current->data);

          free(mxhost);
        }

      else if ( rr_class == C_IN && rr_type == T_NS )
        {
          /* Decode the RR data and add it to the nameservers list */
          status = ares__expand_name_for_response( aptr, abuf, alen, &rr_data,
                                                   &len);
          if ( status != ARES_SUCCESS )
            break;

          snprintf(any_reply_current->type, 16, "NS");
          any_reply_current->name = rr_name;

          any_reply_current->length = strlen(rr_data);
          any_reply_current->data = rr_data;
        }

      else if (rr_class == C_IN && rr_type == T_PTR)
        {
          /* Decode the RR data and set hostname to it. */
          status = ares__expand_name_for_response(aptr, abuf, alen, &rr_data,
                                                  &len);
          if (status != ARES_SUCCESS)
            break;

          snprintf(any_reply_current->type, 16, "PTR");
          any_reply_current->name = rr_name;

          any_reply_current->length = strlen(rr_data);
          any_reply_current->data = rr_data;
        }

      else {
        if (rr_class == C_IN)
          snprintf(any_reply_current->type, 16, "UNK_IN_%hu", rr_type);
        else
          snprintf(any_reply_current->type, 16, "UNK_%hu_%hu", rr_class, rr_type);

        any_reply_current->name = rr_name;
        any_reply_current->data = malloc(rr_len);
        any_reply_current->length = rr_len;
        memcpy(any_reply_current->data, aptr, rr_len);
      }

      aptr += rr_len;
      if (aptr > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }

      if (any_reply_current->name) {
        any_reply_current->next = ares_malloc_data(ARES_DATATYPE_ANY_REPLY);
        any_reply_current = any_reply_current->next;
      }
    }

  // cleanup the last empty struct
  any_reply_current = any_reply_local;
  while (any_reply_current->next) {
    if (any_reply_current->next->name == NULL) {
      ares_free_data(any_reply_current->next);
      any_reply_current->next = NULL;
      break;
    } else
      any_reply_current = any_reply_current->next;
  }

  if (status == ARES_SUCCESS && any_reply_local->name == NULL)
    /* the check for naliases to be zero is to make sure CNAME responses
       don't get caught here */
    status = ARES_ENODATA;

  free(hostname);

  return status;
}
