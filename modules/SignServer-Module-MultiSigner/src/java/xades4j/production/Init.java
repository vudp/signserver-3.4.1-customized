/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.production;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import xades4j.properties.QualifyingProperty;

/**
 *
 * @author Luís
 */
class Init
{
    private Init()
    {
    }

    static void initXMLSec()
    {
        org.apache.xml.security.Init.init();
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        try
        {
            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, ""); //dsign
            ElementProxy.setDefaultPrefix(QualifyingProperty.XADES_XMLNS, "xades"); //xades
            ElementProxy.setDefaultPrefix(QualifyingProperty.XADESV141_XMLNS, "xades141");
        } catch (XMLSecurityException ex)
        {
        }
    }
}
