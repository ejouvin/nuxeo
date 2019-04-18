/*
 * (C) Copyright 2014-2018 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Arnaud Kervern
 */
package org.nuxeo.ecm.platform.oauth2.clients;

import static java.util.Objects.requireNonNull;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static org.nuxeo.ecm.platform.oauth2.clients.OAuth2ClientService.OAUTH2CLIENT_SCHEMA;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.NuxeoException;
import org.nuxeo.ecm.directory.BaseSession;

/**
 * @author <a href="mailto:ak@nuxeo.com">Arnaud Kervern</a>
 * @since 5.9.2
 */
public class OAuth2Client {

    public static final String NAME_FIELD = "name";

    public static final String ID_FIELD = "clientId";

    public static final String SECRET_FIELD = "clientSecret";

    public static final String REDIRECT_URI_FIELD = "redirectURIs";

    public static final String AUTO_GRANT_FIELD = "autoGrant";

    public static final String ENABLED_FIELD = "enabled";

    protected static final Pattern LOCALHOST_PATTERN = Pattern.compile("http://localhost(:\\d+)?(/.*)?");

    /**
     * @since 11.1
     */
    public static final String REDIRECT_URI_SEPARATOR = ",";

    protected String name;

    protected String id;

    protected String secret;

    /**
     * @since 9.2
     */
    protected List<String> redirectURIs;

    /**
     * @since 9.10
     */
    protected boolean autoGrant;

    protected boolean enabled;

    /**
     * @since 9.10
     */
    protected OAuth2Client(String name, String id, String secret, List<String> redirectURIs, boolean autoGrant,
            boolean enabled) {
        this.name = name;
        this.id = id;
        this.secret = secret;
        this.redirectURIs = redirectURIs;
        this.autoGrant = autoGrant;
        this.enabled = enabled;
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    /**
     * @since 9.2
     */
    public List<String> getRedirectURIs() {
        return redirectURIs;
    }

    /**
     * @since 9.10
     */
    public boolean isAutoGrant() {
        return autoGrant;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @since 11.1
     */
    public String getSecret() {
        return secret;
    }

    public static OAuth2Client fromDocumentModel(DocumentModel doc) {
        String name = getProperty(doc, NAME_FIELD, String.class).get();
        String id = getProperty(doc, ID_FIELD, String.class).get();
        boolean autoGrant = getProperty(doc, AUTO_GRANT_FIELD, Boolean.class).get();
        boolean enabled = getProperty(doc, ENABLED_FIELD, Boolean.class).get();
        String secret = getProperty(doc, SECRET_FIELD, String.class).orElse(null);

        String redirectURIsProperty = getProperty(doc, REDIRECT_URI_FIELD, String.class).get();
        List<String> redirectURIs = Arrays.asList(StringUtils.split(redirectURIsProperty, REDIRECT_URI_SEPARATOR));

        return new OAuth2Client(name, id, secret, redirectURIs, autoGrant, enabled);
    }

    /**
     * A redirect URI is considered as valid if and only if:
     * <ul>
     * <li>It is not empty</li>
     * <li>It starts with https, e.g. https://my.redirect.uri</li>
     * <li>It doesn't start with http, e.g. nuxeo://authorize</li>
     * <li>It starts with http://localhost with localhost not part of the domain name, e.g. http://localhost:8080/nuxeo,
     * a counter-example being http://localhost.somecompany.com</li>
     * </ul>
     *
     * @since 9.2
     */
    public static boolean isRedirectURIValid(String redirectURI) {
        String trimmed = redirectURI.trim();
        return !trimmed.isEmpty() && (trimmed.startsWith("https") || !trimmed.startsWith("http")
                || LOCALHOST_PATTERN.matcher(trimmed).matches());
    }

    public boolean isValidWith(String clientId, String clientSecret) {
        // Related to RFC 6749 2.3.1 clientSecret is omitted if empty
        return enabled && id.equals(clientId) && (StringUtils.isEmpty(secret) || secret.equals(clientSecret));
    }

    /**
     * Create {@link DocumentModel} from {@link OAuth2Client}.
     *
     * @param oAuth2Client the oAuth2Client to convert
     * @return the corresponding {@code DocumentModel} of {@code OAuth2Client}
     * @since 11.1
     */
    public static DocumentModel fromOAuth2Client(OAuth2Client oAuth2Client) {
        return BaseSession.createEntryModel(null, OAUTH2CLIENT_SCHEMA, null, getDocumentData(oAuth2Client));
    }

    /**
     * Update {@link DocumentModel} by {@link OAuth2Client}.
     * 
     * @param documentModel the document model to update
     * @param oAuth2Client the new values of document
     * @return the updated {@code DocumentModel}
     */
    public static DocumentModel updateDocument(DocumentModel documentModel, OAuth2Client oAuth2Client) {
        requireNonNull(documentModel, "documentModel model is required");
        requireNonNull(oAuth2Client, "oAuth2Client model is required");
        documentModel.setProperties(OAUTH2CLIENT_SCHEMA, OAuth2Client.getDocumentData(oAuth2Client));
        return documentModel;
    }

    /**
     * Get document properties from {@link OAuth2Client}.
     *
     * @param oAuth2Client the oAuth2Client
     * @return the {@code Map} structure of {@code OAuth2Client}
     * @since 11.1
     */
    protected static Map<String, Object> getDocumentData(OAuth2Client oAuth2Client) {
        validate(oAuth2Client);
        Map<String, Object> values = new HashMap<>();
        values.put(NAME_FIELD, oAuth2Client.getName());
        values.put(ID_FIELD, oAuth2Client.getId());
        values.put(REDIRECT_URI_FIELD, StringUtils.join(oAuth2Client.getRedirectURIs(), REDIRECT_URI_SEPARATOR));
        values.put(AUTO_GRANT_FIELD, oAuth2Client.isAutoGrant());
        values.put(ENABLED_FIELD, oAuth2Client.isEnabled());
        if (StringUtils.isNotEmpty(oAuth2Client.getSecret())) {
            values.put(SECRET_FIELD, oAuth2Client.getSecret());
        }
        return values;
    }

    /**
     * Validate the {@link OAuth2Client}. An {@link OAuth2Client} is valid if his required fields are not empty.
     *
     * @param oAuth2Client the oAuth2Client to validate
     * @throws NuxeoException if oAuth2Client is not valid
     * @since 11.1
     */
    public static void validate(OAuth2Client oAuth2Client) {
        String message = null;
        if (StringUtils.isEmpty(oAuth2Client.getName())) {
            message = "Client name";
        } else if (StringUtils.isEmpty(oAuth2Client.getId())) {
            message = "Client Id";
        } else if (oAuth2Client.getRedirectURIs().isEmpty()) {
            message = "Redirect URIs";
        }

        if (StringUtils.isNotEmpty(message)) {
            throw new NuxeoException(String.format("%s is required", message), SC_BAD_REQUEST);
        }
    }

    /**
     * Get the property value of oAuth2Client from a document model.
     *
     * @param doc the document model
     * @param name the name of the property
     * @param clazz the type of the property
     * @return an {@code Optional} with a present value if the specified value is non-{@code null}, otherwise an empty
     *         {@code Optional}
     * @since 11.1
     */
    public static <T> Optional<T> getProperty(DocumentModel doc, String name, Class<T> clazz) {
        return Optional.ofNullable(doc.getProperty(OAUTH2CLIENT_SCHEMA, name)).map(clazz::cast);
    }

    /**
     * @since 9.2
     */
    @Override
    public String toString() {
        ToStringBuilder builder = new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE);
        return builder.append("name", name)
                      .append("id", id)
                      .append("redirectURIs", redirectURIs)
                      .append("autoGrant", autoGrant)
                      .append("enabled", enabled)
                      .toString();
    }
}
