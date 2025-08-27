/* Copyright 2014 Yubico */

package org.signserver.u2f.yubico.u2f;

import com.google.common.base.Objects;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import org.signserver.u2f.yubico.u2f.crypto.BouncyCastleCrypto;
import org.signserver.u2f.yubico.u2f.crypto.ChallengeGenerator;
import org.signserver.u2f.yubico.u2f.crypto.RandomChallengeGenerator;
import org.signserver.u2f.yubico.u2f.data.DeviceRegistration;
import org.signserver.u2f.yubico.u2f.exceptions.DeviceCompromisedException;
import org.signserver.u2f.yubico.u2f.exceptions.NoEligableDevicesException;
import org.signserver.u2f.yubico.u2f.exceptions.U2fBadInputException;

import java.util.Set;
import org.signserver.u2f.yubico.u2f.data.messages.AuthenticateRequest;
import org.signserver.u2f.yubico.u2f.data.messages.AuthenticateRequestData;
import org.signserver.u2f.yubico.u2f.data.messages.AuthenticateResponse;
import org.signserver.u2f.yubico.u2f.data.messages.RegisterRequestData;
import org.signserver.u2f.yubico.u2f.data.messages.RegisterResponse;

public class U2F {

    private final ChallengeGenerator challengeGenerator;
    private final U2fPrimitives primitives;
    private final boolean validateAppId;



    public U2F() {
        this(true);
    }

    public static U2F withoutAppIdValidation() {
        return new U2F(false);
    }

    public U2F(boolean validateAppId) {
        this.challengeGenerator = new RandomChallengeGenerator();
        primitives = new U2fPrimitives(new BouncyCastleCrypto(), challengeGenerator);
        this.validateAppId = validateAppId;
    }

    /**
     * Initiates a high-level registration of a device, given a set of already registered devices.
     *
     * @param appId   the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *                support logging in from multiple Web Origins.
     * @param devices the devices currently registered to the user.
     * @return a RegisterRequestData, which should be sent to the client and temporarily saved by the server.
     */
    public RegisterRequestData startRegistration(String appId, Iterable<? extends DeviceRegistration> devices) {
    	if(validateAppId) {
            AppId.checkIsValid(appId);
        }
        return new RegisterRequestData(appId, devices, primitives, challengeGenerator);
    }

    public AuthenticateRequestData startAuthentication(String appId, Iterable<? extends DeviceRegistration> devices) throws U2fBadInputException, NoEligableDevicesException {
        if(validateAppId) {
            AppId.checkIsValid(appId);
        }
        return new AuthenticateRequestData(appId, devices, primitives, challengeGenerator);
    }
    
    //RawAuthentificationResponse

    /***
     *
     */
    public DeviceRegistration finishRegistration(RegisterRequestData registerRequestData, RegisterResponse response) throws U2fBadInputException {
        return finishRegistration(registerRequestData, response, null);
    }

    /**
     * Finishes a previously started high-level registration.
     *
     * @param registerRequestData the RegisterResponseData created by calling startRegistration
     * @param response            The response from the device/client.
     * @param facets              A list of valid facets to verify against.
     * @return a DeviceRegistration object, holding information about the registered device. Servers should
     * persist this.
     * @throws org.signserver.u2f.yubico.u2f.exceptions.U2fBadInputException
     */
    public DeviceRegistration finishRegistration(RegisterRequestData registerRequestData, RegisterResponse response, Set<String> facets) throws U2fBadInputException {
        return primitives.finishRegistration(registerRequestData.getRegisterRequest(response), response, facets);
    }

    /**
     * @see U2F#finishAuthentication(com.yubico.u2f.data.messages.AuthenticateRequestData, com.yubico.u2f.data.messages.AuthenticateResponse, Iterable, java.util.Set)
     */
    public DeviceRegistration finishAuthentication(AuthenticateRequestData authenticateRequestData, AuthenticateResponse response, Iterable<? extends DeviceRegistration> devices) throws U2fBadInputException, DeviceCompromisedException {
        return finishAuthentication(authenticateRequestData, response, devices, null);
    }

    /**
     * Finishes a previously started high-level authentication.
     *
     * @param authenticateRequestData the AuthenticateRequestData created by calling startAuthentication
     * @param response                the response from the device/client.
     * @param devices                 the devices currently registered to the user.
     * @param facets                  A list of valid facets to verify against.
     * @return The (updated) DeviceRegistration that was authenticated against.
     * @throws org.signserver.u2f.yubico.u2f.exceptions.U2fBadInputException
     */
    public DeviceRegistration finishAuthentication(AuthenticateRequestData authenticateRequestData, AuthenticateResponse response, Iterable<? extends DeviceRegistration> devices, Set<String> facets) throws U2fBadInputException, DeviceCompromisedException {
    	final AuthenticateRequest request = authenticateRequestData.getAuthenticateRequest(response);
        DeviceRegistration device = Iterables.find(devices, new Predicate<DeviceRegistration>() {
            @Override
            public boolean apply(DeviceRegistration input) {
                return Objects.equal(request.getKeyHandle(), input.getKeyHandle());
            }
        });
    
        if (device.isCompromised()) {
            throw new DeviceCompromisedException(device, "The device is marked as possibly compromised, and cannot be authenticated");
        }
        primitives.finishAuthentication(request, response, device, facets);
        return device;
    }
}
