/* sophos.c */
static char *id=
     "@(#) $Id: sophos.c,v 1.21 2002/10/04 19:07:01 bitbytebit Exp $";
/*
   Copyright (C) 2002
        Chris Kennedy, The Groovy Organization.

   The Blackhole is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Blackhole is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   For a copy of the GNU Library General Public License
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  or go to http://www.gnu.org
*/
/* Sophos Virus Scanning Code */

#ifndef USE_MCONFIG
#include "config.h"
#endif

#include "virus.h"

#if VIRUS_SCANNER == SOPHOSSDK
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "csavi2c.h"
#include "sophos.h"

#include "my_string.h"
#include "max.h"
#include "misc.h"

extern int DEBUG;
extern char *progname;
extern char *virus_type;
extern int found_virus;

void sophos_infected(HRESULT, CIEnumSweepResults *);

#if SOPHOS_RIPMIME == 1
int mime_parse(char *);
extern char *mime_dir;
int rmdir_r_sophos(char *);
#endif

int sophos(char *filename)
{
  CISavi2 *pSAVI;
  CISweepClassFactory2 *pFactory;
  CIEnumSweepResults *scan_results = NULL;
  HRESULT hr;
  int i;
#if SOPHOS_RIPMIME == 1
  DIR *d;
  struct dirent *dir;
  char *message;
#endif

#ifdef USE_SOPHOS_BETA
  DEFINE_GUID(SOPHOS_CLASSID_SAVI, 0x91c4c540, 0x9fdd, 0x11d2, 0xaf, 0xaa, 0x00, 0x10, 0x5a, 0x30, 0x5a, 0x2b);
  #define SOPHOS_CLSID_SAVI2 SOPHOS_CLASSID_SAVI
#endif

  /* Initialize the Sophos Scan Engine */
  hr =
    DllGetClassObject((REFIID) & SOPHOS_CLSID_SAVI2,
                      (REFIID) & SOPHOS_IID_CLASSFACTORY2, (void **) &pFactory);

  if(!(hr == SOPHOS_S_OK)) {
    if(DEBUG)
      fprintf(stderr, "ERROR: Could not initialize SAVI class/object\n");
    return 1;
  } else {
    hr =
      pFactory->pVtbl->CreateInstance(pFactory, NULL, &SOPHOS_IID_SAVI2,
                                      (void **) &pSAVI);

    pFactory->pVtbl->Release(pFactory);

    /* If Sophos setup is ok, scan file */
    if(hr == SOPHOS_S_OK) {
      hr = pSAVI->pVtbl->InitialiseWithMoniker(pSAVI, progname);
      if(SOPHOS_FAILED(hr)) {
        fprintf(stderr, "ERROR: Failed to initialize SAVI [%ld]", (long) hr);
        pSAVI->pVtbl->Release(pSAVI);
        pSAVI = NULL;
        return 1;
      }

      /* set Recursion depth */
      hr = pSAVI->pVtbl->SetConfigValue(pSAVI,
                                        SOPHOS_MAX_RECURSION_DEPTH,
                                        SOPHOS_TYPE_U16, "16");
      if(SOPHOS_FAILED(hr))
        fprintf(stderr, "ERROR: Failed to set %s to \"16\"\n",
                SOPHOS_MAX_RECURSION_DEPTH);

      /* Configure Sophos */
      for(i = 0; sophos_settings[i].option != NULL; i++) {
#if WITH_DEBUG == 2
        if(DEBUG)
          fprintf(stderr, "setting %s to \"%s\"\n",
                  sophos_settings[i].option, sophos_settings[i].value);
#endif
        hr = pSAVI->pVtbl->SetConfigValue(pSAVI,
                                          sophos_settings[i].option,
                                          SOPHOS_TYPE_U32,
                                          sophos_settings[i].value);
        if(SOPHOS_FAILED(hr))
          fprintf(stderr, "ERROR: Failed to set %s to \"%s\"\n",
                  sophos_settings[i].option, sophos_settings[i].value);
      }

#if SOPHOS_RIPMIME == 1
      /* Use RipMime library and break apart message, and scan each file */
      if(bh_assert(mime_parse(filename) == 1))
        return 0;
      if(bh_assert(mime_dir == NULL))
        return 0;

      d = opendir(mime_dir);
      if(bh_assert(d == NULL)) {
        fprintf(stderr, "%s: Not able to open dir %s!\n", __FILE__, mime_dir);
        return 1;
      }
  
      if(DEBUG)
        fprintf(stderr, "Mime Dir: %s\n", mime_dir);

      while((dir = readdir(d)) != NULL) {
        if(strncmp(dir->d_name, ".", 1) == 0)
          continue;
    
        /* Message File */
        strsize = 
             my_strlen(mime_dir) + (sizeof(dir->d_name) * sizeof(char)) + 1;
        message = malloc(strsize + 1);
        if(bh_assert(message == NULL))
          return 1;
        snprintf(message, strsize + 1,
                 "%s/%s", mime_dir, dir->d_name);

#if WITH_DEBUG == 1
        if(DEBUG)
          fprintf(stderr, "Scanning: %s\n", message);
#endif
    
        /* Scan File */
        if(found_virus == 0) {
          hr =
            pSAVI->pVtbl->SweepFile(pSAVI, message,
                                  (REFIID) & SOPHOS_IID_ENUM_SWEEPRESULTS,
                                  (void **) &scan_results);
  
          /* Check Results */
          switch (hr) {
          case SOPHOS_S_OK:
            break;
  
          case SOPHOS_SAVI2_ERROR_VIRUSPRESENT:
            sophos_infected(hr, scan_results);
            break;
  
          default:
            break;
          }
        }
        unlink(message);
        free(message);
      }
      closedir(d);
      rmdir(mime_dir);
#else
      /* Scan File */
      hr =
        pSAVI->pVtbl->SweepFile(pSAVI, filename,
                                (REFIID) & SOPHOS_IID_ENUM_SWEEPRESULTS,
                                (void **) &scan_results);

      /* Check Results */
      switch (hr) {
      case SOPHOS_S_OK:
        break;

      case SOPHOS_SAVI2_ERROR_VIRUSPRESENT:
        sophos_infected(hr, scan_results);
        break;

      default:
        break;
      }
#endif
      if(pSAVI) {
        pSAVI->pVtbl->Terminate(pSAVI);
        pSAVI->pVtbl->Release(pSAVI);
      }
    }
  }
  return 0;
}

void sophos_infected(HRESULT hr, CIEnumSweepResults * scan_results)
{
  OLECHAR virusName[256];
  CISweepResults *details = NULL;
  SOPHOS_ULONG fetched;

  /* Read the results */
  while(scan_results->pVtbl->
        Next(scan_results, 1, (void **) &details, &fetched) == SOPHOS_S_OK) {
    hr =
      details->pVtbl->GetVirusName(details, sizeof(virusName) - 1,
                                   (LPOLESTR) virusName, NULL);

    /* Failed at reading results */
    if(SOPHOS_FAILED(hr)) {
      if(DEBUG)
        fprintf(stderr, "Sophos ERROR: Could not get a virus name");
    }

    /* Setup external variables */
    strsize = sizeof(virusName);
    virus_type = malloc(strsize + 1);
    if(virus_type != NULL) {
      my_strlcpy(virus_type, virusName, strsize+1);
      virus_type[strsize] = (char)'\0';
      found_virus = 1;
    }
  }
}
#endif
