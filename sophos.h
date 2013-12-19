/* sophos.h */
/* Sophos variables taken from Vanja Hrustic (vanja@pobox.com)
 Sophie Author.
*/
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
#ifndef _SOPHOS_H
#define _SOPHOS_H 1

/* Define this for Sophos Beta to work, libsav.3.x */
/* #define USE_SOPHOS_BETA */

/* Undocumented Settings */
#define SOPHOS_LHA_DECOMPRESSION        _T("Lha")
#define SOPHOS_SFX_HANDLING             _T("SfxArchives")
#define SOPHOS_TNEF_HANDLING            _T("TnefAttachmentHandling")
#define SOPHOS_MSCOMPRESS_HANDLING      _T("MSCompress")
#define SOPHOS_OF95DECRYPT_HANDLING     _T("OF95DecryptHandling")
#define SOPHOS_DELETE_ALL_MACROS        _T("DeleteAllMacros")

/* Engine 2.5 - IDE 3.48 (29-Jul-2001) */
#define SOPHOS_VBE                      _T("Vbe")
#define SOPHOS_EXEC_FILE_DISINFECTION   _T("ExecFileDisinfection")
#define SOPHOS_VISIO_FILE_HANDLING      _T("VisioFileHandling")


/* Engine 2.9 - IDE 3.55 (25-Feb-2002) */
#define SOPHOS_MIME                     _T("Mime")
#define SOPHOS_ACTIVE_MIME_HANDLING     _T("ActiveMimeHandling")
#define SOPHOS_DEL_VBA5_PROJECT         _T("DelVBA5Project")
#define SOPHOS_SCRAP_OBJECT_HANDLING    _T("ScrapObjectHandling")
#define SOPHOS_SRP_STREAM_HANDLING      _T("SrpStreamHandling")
#define SOPHOS_OFFICE2001_HANDLING      _T("Office2001Handling")
#define SOPHOS_UPX                      _T("Upx")
#define SOPHOS_MAC                      _T("Mac")
#define SOPHOS_SAFE_MAC_DF_HANDLING     _T("SafeMacDfHandling")
#define SOPHOS_PALM_PILOT_HANDLING      _T("PalmPilotHandling")

/* 13-May-2002 - IDE 3.57, engine 2.10 */
#define SOPHIE_SOPHOS_MBIN                                      "0"
#define SOPHIE_SOPHOS_EXCEL_FORMULA                             "1"
#define SOPHIE_SOPHOS_PDF                                       "0"
#define SOPHIE_SOPHOS_RTF                                       "1"
#define SOPHIE_SOPHOS_HTML                                      "1"
#define SOPHIE_SOPHOS_ELF                                       "1"
#define SOPHIE_SOPHOS_WORDB                                     "1"

#define ON  "1"
#define OFF "0"

struct sophos_settings
{
  char *option;
  char *value;
}

sophos_settings[] =
{
  /* NamespaceSupport */
  {
  SOPHOS_NAMESPACE_SUPPORT, OFF}
  ,
    /* FullSweep */
  {
  SOPHOS_DO_FULL_SWEEP, ON}
  ,
    /* DynamicDecompression */
  {
  SOPHOS_DYNAMIC_DECOMPRESSION, ON}
  ,
    /* FullMacroSweep */
  {
  SOPHOS_FULL_MACRO_SWEEP, ON}
  ,
    /* OLE2Handling */
  {
  SOPHOS_OLE2_HANDLING, ON}
  ,
    /* IgnoreTemplateBit */
  {
  SOPHOS_IGNORE_TEMPLATE_BIT, ON}
  ,
    /* VBA3Handling */
  {
  SOPHOS_VBA3_HANDLING, ON}
  ,
    /* VBA5Handling */
  {
  SOPHOS_VBA5_HANDLING, ON}
  ,
    /* OF95DecryptHandling */
  {
  SOPHOS_OF95_DECRYPT_HANDLING, ON}
  ,
    /* HelpHandling */
  {
  SOPHOS_HELP_HANDLING, ON}
  ,
    /* DecompressVBA5 */
  {
  SOPHOS_DECOMPRESS_VBA5, ON}
  ,
    /* Emulation */
  {
  SOPHOS_DO_EMULATION, ON}
  ,
    /* PEHandling */
  {
  SOPHOS_PE_HANDLING, ON}
  ,
    /* ExcelFormulaHandling */
  {
  SOPHOS_XF_HANDLING, ON}
  ,
    /* PowerPointMacroHandling */
  {
  SOPHOS_PM97_HANDLING, ON}
  ,
    /* PowerPointEmbeddedHandling */
  {
  SOPHOS_PPT_EMBD_HANDLING, ON}
  ,
    /* ProjectHandling */
  {
  SOPHOS_PROJECT_HANDLING, ON}
  ,
    /* ZipDecompression */
  {
  SOPHOS_ZIP_DECOMPRESSION, ON}
  ,
    /* ArjDecompression */
  {
  SOPHOS_ARJ_DECOMPRESSION, ON}
  ,
    /* RarDecompression */
  {
  SOPHOS_RAR_DECOMPRESSION, ON}
  ,
    /* UueDecompression */
  {
  SOPHOS_UUE_DECOMPRESSION, ON}
  ,
    /* GZipDecompression */
  {
  SOPHOS_GZIP_DECOMPRESSION, ON}
  ,
    /* TarDecompression */
  {
  SOPHOS_TAR_DECOMPRESSION, ON}
  ,
    /* CmzDecompression */
  {
  SOPHOS_CMZ_DECOMPRESSION, ON}
  ,
    /* HqxDecompression */
  {
  SOPHOS_HQX_DECOMPRESSION, ON}
  ,
    /* MbinDecompression */
  {
  SOPHOS_MBIN_DECOMPRESSION, ON}
  ,
    /* LoopBackEnabled */
  {
  SOPHOS_LOOPBACK_ENABLED, OFF}
  ,
    /* Lha */
  {
  SOPHOS_LHA_DECOMPRESSION, ON}
  ,
    /* SfxArchives */
  {
  SOPHOS_SFX_HANDLING, ON}
  ,
    /* TnefAttachmentHandling */
  {
  SOPHOS_TNEF_HANDLING, ON}
  ,
    /* MSCompress */
  {
  SOPHOS_MSCOMPRESS_HANDLING, ON}
  ,
    /* OF95DecryptHandling */
  {
  SOPHOS_OF95DECRYPT_HANDLING, ON}
  ,
    /* DeleteAllMacros */
  {
  SOPHOS_DELETE_ALL_MACROS, OFF}
  ,
    /* Vbe */
  {
  SOPHOS_VBE, ON}
  ,
    /* ExecFileDisinfection */
  {
  SOPHOS_EXEC_FILE_DISINFECTION, OFF}
  ,
    /* VisioFileHandling */
  {
  SOPHOS_VISIO_FILE_HANDLING, ON}
  ,
    /* Mime */
  {
  SOPHOS_MIME, ON}
  ,
    /* ActiveMimeHandling */
  {
  SOPHOS_ACTIVE_MIME_HANDLING, ON}
  ,
    /* DelVBA5Project */
  {
  SOPHOS_DEL_VBA5_PROJECT, ON}
  ,
    /* ScrapObjectHandling */
  {
  SOPHOS_SCRAP_OBJECT_HANDLING, ON}
  ,
    /* SrpStreamHandling */
  {
  SOPHOS_SRP_STREAM_HANDLING, ON}
  ,
    /* Office2001Handling */
  {
  SOPHOS_OFFICE2001_HANDLING, ON}
  ,
    /* Upx */
  {
  SOPHOS_UPX, ON}
  ,
    /* Mac */
  {
  SOPHOS_MAC, ON}
  ,
    /* SafeMacDfHandling */
  {
  SOPHOS_SAFE_MAC_DF_HANDLING, OFF}
  ,
    /* PalmPilotHandling */
  {
  SOPHOS_PALM_PILOT_HANDLING, ON}
  , {
  NULL, NULL}
};

#endif /* _SOPHOS_H */
