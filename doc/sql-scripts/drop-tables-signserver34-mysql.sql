-- Dropping tables for SignServer 3.4.x on MySQL
-- ------------------------------------------------------
-- Version: $Id: drop-tables-signserver34-mysql.sql 3233 2013-01-22 15:42:17Z netmackan $
-- Comment: 


--
-- Drop table `AuditRecordData`
--
DROP TABLE IF EXISTS `AuditRecordData`;

--
-- Drop table `GlobalConfigData`
--
DROP TABLE IF EXISTS `GlobalConfigData`;


--
-- Drop table `signerconfigdata`
--
DROP TABLE IF EXISTS `signerconfigdata`;


--
-- Drop table `KeyUsageCounter`
--
DROP TABLE IF EXISTS `KeyUsageCounter`;


--
-- Drop table `ArchiveData`
--
DROP TABLE IF EXISTS `ArchiveData`;


--
-- Drop table `enckeydata`
--
DROP TABLE IF EXISTS `enckeydata`;


--
-- Drop table `groupkeydata`
--
DROP TABLE IF EXISTS `groupkeydata`;


--
-- Drop table `SEQUENCE`
--
DROP TABLE IF EXISTS `SEQUENCE`;

DROP TABLE IF EXISTS `CHANNEL`;
DROP TABLE IF EXISTS `IPLIST`;


-- End
