package es.apb.firma.ws.interceptor;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.cxf.binding.soap.interceptor.SoapHeaderInterceptor;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.ws.addressing.EndpointReferenceType;
import org.apache.log4j.Logger;

import es.apb.firma.ws.util.Configuracion;

public class BasicAuthAuthorizationInterceptor extends SoapHeaderInterceptor {

    protected Logger log = Logger.getLogger(getClass());

    @Override
    public void handleMessage(final Message message) throws Fault {

        // Si no esta habilitado, no procesamos
        if (!Configuracion.getInstance().isSecurityEnabled()) {
            return;
        }

        // This is set by CXF
        final AuthorizationPolicy policy = message
                .get(AuthorizationPolicy.class);
        // If the policy is not set, the user did not specify
        // credentials. A 401 is sent to the client to indicate
        // that authentication is required
        if (policy == null) {
            log.error("Invalid username or password");
            sendErrorResponse(message, HttpURLConnection.HTTP_UNAUTHORIZED);
            return;
        }
        // Verify the password
        if (!validatePassword(policy.getUserName(), policy.getPassword())) {
            log.error("Invalid username or password for user: "
                    + policy.getUserName());
            sendErrorResponse(message, HttpURLConnection.HTTP_FORBIDDEN);
        }

    }

    private void sendErrorResponse(final Message message, final int responseCode) {
        final Message outMessage = getOutMessage(message);
        outMessage.put(Message.RESPONSE_CODE, responseCode);
        // Set the response headers
        // final Map responseHeaders = message.get( Message.PROTOCOL_HEADERS);
        final Map<String, List<String>> responseHeaders = (Map<String, List<String>>) message
                .get(Message.PROTOCOL_HEADERS);
        if (responseHeaders != null) {
            responseHeaders.put("WWW-Authenticate",
                    Arrays.asList(new String[] {"Basic realm=realm"}));
            responseHeaders.put("Content-Length",
                    Arrays.asList(new String[] {"0"}));
        }
        message.getInterceptorChain().abort();
        try {
            getConduit(message).prepare(outMessage);
            close(outMessage);
        } catch (final IOException e) {
            log.warn(e.getMessage(), e);
        }
    }

    private Message getOutMessage(final Message inMessage) {
        final Exchange exchange = inMessage.getExchange();
        Message outMessage = exchange.getOutMessage();
        if (outMessage == null) {
            final Endpoint endpoint = exchange.get(Endpoint.class);
            outMessage = endpoint.getBinding().createMessage();
            exchange.setOutMessage(outMessage);
        }
        outMessage.putAll(inMessage);
        return outMessage;
    }

    private Conduit getConduit(final Message inMessage) throws IOException {
        final Exchange exchange = inMessage.getExchange();
        final EndpointReferenceType target = exchange
                .get(EndpointReferenceType.class);
        final Conduit conduit = exchange.getDestination().getBackChannel(
                inMessage, null, target);
        exchange.setConduit(conduit);
        return conduit;
    }

    private void close(final Message outMessage) throws IOException {
        final OutputStream os = outMessage.getContent(OutputStream.class);
        os.flush();
        os.close();
    }

    private boolean validatePassword(final String pUserName,
            final String pPassword) {
        return Configuracion.getInstance().getUser().equals(pUserName)
                && Configuracion.getInstance().getPassword().equals(pPassword);
    }
}