/*
 * (C) Copyright 2019 Nuxeo (http://nuxeo.com/) and others.
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
 *     Salem Aouana
 */

package org.nuxeo.ecm.platform.oauth2.clients;

import static java.util.Objects.requireNonNullElse;
import static org.nuxeo.ecm.core.io.registry.reflect.Instantiations.SINGLETON;
import static org.nuxeo.ecm.core.io.registry.reflect.Priorities.REFERENCE;
import static org.nuxeo.ecm.platform.oauth2.clients.OAuth2Client.NAME_FIELD;
import static org.nuxeo.ecm.platform.oauth2.clients.OAuth2Client.REDIRECT_URI_FIELD;

import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.BooleanUtils;
import org.nuxeo.ecm.core.io.marshallers.json.EntityJsonReader;
import org.nuxeo.ecm.core.io.registry.reflect.Setup;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * @since 11.1
 */
@Setup(mode = SINGLETON, priority = REFERENCE)
public class OAuth2ClientReader extends EntityJsonReader<OAuth2Client> {

    public OAuth2ClientReader() {
        super(OAuth2ClientWriter.ENTITY_TYPE);
    }

    @Override
    protected OAuth2Client readEntity(JsonNode jn) {
        String name = getStringField(jn, NAME_FIELD);
        List<String> redirectURIs = requireNonNullElse(getStringListField(jn, REDIRECT_URI_FIELD),
                Collections.emptyList());
        String clientId = getStringField(jn, "id");
        String secret = getStringField(jn, "secret");
        boolean autoGrant = BooleanUtils.toBoolean(getBooleanField(jn, "isAutoGrant"));
        boolean enabled = BooleanUtils.toBoolean(getBooleanField(jn, "isEnabled"));
        return new OAuth2Client(name, clientId, secret, redirectURIs, autoGrant, enabled);
    }
}
