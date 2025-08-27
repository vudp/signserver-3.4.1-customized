package org.signserver.validationservice.server.dcsigner.signprocess.handlers;

public interface ElDCSignRequestListener
{
    byte[] signRequested(ElDCSignRequestEvent p0);
}
