package org.signserver.validationservice.server.dcsigner.signprocess;

import java.util.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;
import org.signserver.validationservice.server.dcsigner.signprocess.handlers.ElDCOperationHandler;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;
import java.io.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import javax.xml.transform.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class ElDCStandardServer
{
    protected ArrayList<ElDCOperationHandler> operationHandlers;
    protected ElDCAsyncState state;
    
    public ElDCStandardServer() {
        this.operationHandlers = new ArrayList<ElDCOperationHandler>();
        this.state = new ElDCAsyncState();
    }
    
    public int addOperationHandler(final ElDCOperationHandler elDCOperationHandler) {
        this.operationHandlers.add(elDCOperationHandler);
        return this.operationHandlers.size() - 1;
    }
    
    public void clearOperationHandlers() {
        this.operationHandlers.clear();
    }
    
    public int getOperationHandlerCount() {
        return this.operationHandlers.size();
    }
    
    public ElDCOperationHandler getOperationHandler(final int n) {
        return this.operationHandlers.get(n);
    }
    
    public void removeOperationHandler(final ElDCOperationHandler elDCOperationHandler) {
        this.operationHandlers.remove(elDCOperationHandler);
    }
    
    protected void processState(final Element element, final Element element2) throws Exception {
        if (!element.getNodeName().equalsIgnoreCase("SecureBlackboxAsyncState")) {
            throw new ElDCServerException(String.format("Unsupported state root document: %s", element.getNodeName()));
        }
        final String loadStringFromXML = ElDCUtils.loadStringFromXML(element, "Type", null, false);
        if (loadStringFromXML == null || !loadStringFromXML.equalsIgnoreCase("standard")) {
            throw new ElDCServerException(String.format("Unsupported state type: %s", loadStringFromXML));
        }
        this.state.loadFromXML(element);
        final ElDCAsyncState elDCAsyncState = new ElDCAsyncState();
        for (int i = 0; i < this.state.getMessages().getCount(); ++i) {
            if (this.state.getMessages().getMessage(i) instanceof ElDCOperationRequestMessage) {
                for (int j = 0; j < this.operationHandlers.size(); ++j) {
                    final ElDCOperationRequestMessage elDCOperationRequestMessage = (ElDCOperationRequestMessage)this.state.getMessages().getMessage(i);
                    if (this.operationHandlers.get(j).isOperationSupported(elDCOperationRequestMessage.getOperation(), elDCOperationRequestMessage.getOperationID())) {
                        ElDCBaseMessage process = this.operationHandlers.get(j).process(elDCOperationRequestMessage);
                        if (process == null) {
                            process = new ElDCBaseMessage(elDCOperationRequestMessage);
                        }
                        elDCAsyncState.getMessages().add(process, false);
                        break;
                    }
                }
            }
            else if (this.state.getMessages().getMessage(i).getClass().getSimpleName().equals("ElDCBaseMessage")) {
                final ElDCBaseMessage elDCBaseMessage = new ElDCBaseMessage();
                elDCBaseMessage.assign(this.state.getMessages().getMessage(i));
                elDCAsyncState.getMessages().add(elDCBaseMessage, false);
            }
            else {
                final ElDCErrorMessage elDCErrorMessage = new ElDCErrorMessage();
                elDCErrorMessage.setCode(0);
                elDCErrorMessage.setErrorMessage("Unexpected message");
                elDCAsyncState.getMessages().add(elDCErrorMessage, false);
            }
        }
        elDCAsyncState.setStateType("standard");
        elDCAsyncState.setStateSubtypes(this.state.getStateSubtypes());
        elDCAsyncState.saveToXML(element2);
    }
    
    public void process(final InputStream is, final OutputStream outputStream) throws Exception {
        final DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        final Element documentElement = documentBuilder.parse(is).getDocumentElement();
        documentElement.normalize();
        if (!documentElement.getNodeName().equalsIgnoreCase("SecureBlackboxAsyncState")) {
            throw new ElDCServerException(String.format("Unsupported state type: %s", documentElement.getNodeName()));
        }
        final String loadStringFromXML = ElDCUtils.loadStringFromXML(documentElement, "Type", null, false);
        if (loadStringFromXML != null && loadStringFromXML.equalsIgnoreCase("standard")) {
            final Document document = documentBuilder.newDocument();
            document.setXmlStandalone(true);
            final Element element = document.createElement("SecureBlackboxAsyncState");
            document.appendChild(element);
            this.processState(documentElement, element);
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(outputStream));
        }
    }
}
