-- Dropping tables for SignServer 3.4.x on Oracle
-- ------------------------------------------------------
-- Version: $Id: drop-tables-signserver34-oracle.sql 3345 2013-02-13 13:43:40Z netmackan $
-- Comment: 


--
-- Drop table `AuditRecordData`
--
DROP TABLE "AUDITRECORDDATA";


--
-- Drop table `GlobalConfigurationData`
--
DROP TABLE "GLOBALCONFIGDATA";


--
-- Drop table `signerconfigdata`
--
DROP TABLE "SIGNERCONFIGDATA";


--
-- Drop table `KeyUsageCounter`
--
DROP TABLE "KEYUSAGECOUNTER";


--
-- Drop table `ArchiveData`
--
DROP TABLE "ARCHIVEDATA";


--
-- Drop table `enckeydata`
--
DROP TABLE "ENCKEYDATA";


--
-- Drop table `groupkeydata`
--
DROP TABLE "GROUPKEYDATA";


-- End
