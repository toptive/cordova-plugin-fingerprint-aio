import Foundation
import LocalAuthentication

enum PluginError: Int {
    case BIOMETRIC_UNKNOWN_ERROR = -100
    case BIOMETRIC_UNAVAILABLE = -101
    case BIOMETRIC_AUTHENTICATION_FAILED = -102
    case BIOMETRIC_PERMISSION_NOT_GRANTED = -105
    case BIOMETRIC_NOT_ENROLLED = -106
    case BIOMETRIC_DISMISSED = -108
    case BIOMETRIC_SCREEN_GUARD_UNSECURED = -110
    case BIOMETRIC_LOCKED_OUT = -111
    case BIOMETRIC_SECRET_NOT_FOUND = -113
}

@objc(Fingerprint) class Fingerprint : CDVPlugin {

    struct ErrorCodes {
        var code: Int
    }

    @objc(isAvailable:)
    func isAvailable(_ command: CDVInvokedUrlCommand) {
        let authenticationContext = LAContext();
        var biometryType = "finger";
        var errorResponse: [AnyHashable: Any] = [
            "code": 0,
            "message": "Not Available"
        ];
        var error: NSError?;
        let policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics;
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Not available");
        let available = authenticationContext.canEvaluatePolicy(policy, error: &error);

        var results: [String : Any]

        if (error != nil) {
            biometryType = "none";
            errorResponse["code"] = error?.code;
            errorResponse["message"] = error?.localizedDescription;
        }

        if (available == true) {
            if #available(iOS 11.0, *) {
                switch (authenticationContext.biometryType) {
                case .none:
                    biometryType = "none";
                    
                    break;
                case .touchID:
                    biometryType = "finger";
                    
                    break;
                case .faceID:
                    biometryType = "face"
                    
                    break;
                @unknown default:
                    biometryType = "none";
                }
            }

            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: biometryType);
        } else {
            var code: Int;
            switch (error!._code) {
                case Int(kLAErrorBiometryNotAvailable):
                    code = PluginError.BIOMETRIC_UNAVAILABLE.rawValue;

                    break;
                case Int(kLAErrorBiometryNotEnrolled):
                    code = PluginError.BIOMETRIC_NOT_ENROLLED.rawValue;
                    
                    break;
                default:
                    code = PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue;

                    break;
            }

            results = ["code": code, "message": error!.localizedDescription];
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: results);
        }

        commandDelegate.send(pluginResult, callbackId:command.callbackId);
    }
    
    @objc(authenticate:)
    func authenticate(_ command: CDVInvokedUrlCommand){
        let data  = command.arguments[0] as AnyObject?;
        let mode = data?["mode"] as? String;
        
        switch mode {
            case "encrypt":
                let secret = data?["secret"] as! String;
                self.encryptSecret(secret, command: command);
            
            break;
            case "decrypt":
                let secret = data?["secret"] as! String;
                self.decryptSecret(secret, command: command);
            
                break;
            default:
                justAuthenticate(command);
        }
    }

    func justAuthenticate(_ command: CDVInvokedUrlCommand) {
        let authenticationContext = LAContext();
        let errorResponse: [AnyHashable: Any] = [
            "message": "Something went wrong"
        ];
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResponse);
        var reason = "Authentication";
        var policy: LAPolicy = .deviceOwnerAuthentication;
        let data = command.arguments[0] as AnyObject?;

        if let disableBackup = data?["disableBackup"] as! Bool? {
            if disableBackup {
                authenticationContext.localizedFallbackTitle = "";
                policy = .deviceOwnerAuthenticationWithBiometrics;
            } else {
                if let fallbackButtonTitle = data?["fallbackButtonTitle"] as! String? {
                    authenticationContext.localizedFallbackTitle = fallbackButtonTitle;
                } else {
                    authenticationContext.localizedFallbackTitle = "Use Pin";
                }
            }
        }

        // Localized reason
        if let description = data?["description"] as! String? {
            reason = description;
        }

        authenticationContext.evaluatePolicy(
            policy,
            localizedReason: reason,
            reply: { [unowned self] (success, error) -> Void in
                if (success) {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: "Success");
                } else {
                    if (error != nil) {

                        var errorCodes = [Int: ErrorCodes]()
                        var errorResult: [String : Any] = [
                            "code": PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue,
                            "message": error?.localizedDescription ?? ""
                        ];

                        errorCodes[1] = ErrorCodes(code: PluginError.BIOMETRIC_AUTHENTICATION_FAILED.rawValue)
                        errorCodes[2] = ErrorCodes(code: PluginError.BIOMETRIC_DISMISSED.rawValue)
                        errorCodes[5] = ErrorCodes(code: PluginError.BIOMETRIC_SCREEN_GUARD_UNSECURED.rawValue)
                        errorCodes[6] = ErrorCodes(code: PluginError.BIOMETRIC_UNAVAILABLE.rawValue)
                        errorCodes[7] = ErrorCodes(code: PluginError.BIOMETRIC_NOT_ENROLLED.rawValue)
                        errorCodes[8] = ErrorCodes(code: PluginError.BIOMETRIC_LOCKED_OUT.rawValue)

                        let errorCode = abs(error!._code)
                        if let e = errorCodes[errorCode] {
                           errorResult = ["code": e.code, "message": error!.localizedDescription];
                        }

                        pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
                    }
                }
                self.commandDelegate.send(pluginResult, callbackId:command.callbackId);
            }
        );
    }

    func encryptSecret(_ secretStr: String, command: CDVInvokedUrlCommand) {
        var pluginResult: CDVPluginResult
        
        do {
            let password = try fetchOrCreatePassword(command: command);
            let result = try encryptMessage(message: secretStr, encryptionKey: password);
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: result);
        } catch {
            var code = PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue
            var message = error.localizedDescription
            if let err = error as? KeychainError {
                code = err.pluginError.rawValue
                message = err.localizedDescription
            }
            let errorResult = ["code": code, "message": message] as [String : Any]
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
        }

        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
        return
    }


    func decryptSecret(_ secretStr: String, command: CDVInvokedUrlCommand) {
        var pluginResult: CDVPluginResult

        do {
            let password = try fetchOrCreatePassword(command: command);
            let result = try decryptMessage(encryptedMessage: secretStr, encryptionKey: password);
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: result);
        } catch {
            var code = PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue
            var message = error.localizedDescription
            if let err = error as? KeychainError {
                code = err.pluginError.rawValue
                message = err.localizedDescription
            }
            let errorResult = ["code": code, "message": message] as [String : Any]
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
        }
        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
    }
    
    func fetchOrCreatePassword(command: CDVInvokedUrlCommand) throws -> Data {
        let data = command.arguments[0] as AnyObject?
        let invalidateOnEnrollment = (data?["invalidateOnEnrollment"] as? Bool) ?? false
        var prompt = "Authentication"
        if let description = data?["description"] as! String? {
            prompt = description
        }

        let secret = Secret()
        
        do { // try to save pasword, if already exists this will trow an exception
            try secret.save(prompt: prompt, invalidateOnEnrollment: invalidateOnEnrollment, secret: RNCryptor.randomData(ofLength: 128))
        } catch {}
        
        return try secret.load(prompt: prompt, invalidateOnEnrollment: invalidateOnEnrollment);
    }
    
    func encryptMessage(message: String, encryptionKey: Data) throws -> String {
        let messageData = message.data(using: .utf8)!
        let password = String(decoding: encryptionKey, as: UTF8.self)
        let cipherData = RNCryptor.encrypt(data: messageData, withPassword: password)
        return cipherData.base64EncodedString()
    }

    func decryptMessage(encryptedMessage: String, encryptionKey: Data) throws -> String {
        let encryptedData = Data.init(base64Encoded: encryptedMessage)!
        let password = String(decoding: encryptionKey, as: UTF8.self)
        let decryptedData = try RNCryptor.decrypt(data: encryptedData, withPassword: password)
        let decryptedString = String(data: decryptedData, encoding: .utf8)!

        return decryptedString
    }

    override func pluginInitialize() {
        super.pluginInitialize()
    }

}

/// Keychain errors we might encounter.
struct KeychainError: Error {
    var status: OSStatus

    var localizedDescription: String {
        if #available(iOS 11.3, *) {
            if let result = SecCopyErrorMessageString(status, nil) as String? {
                return result
            }
        }
        switch status {
            case errSecItemNotFound:
                return "Secret not found"
            case errSecUserCanceled:
                return "Biometric dissmissed"
            case errSecAuthFailed:
                return "Authentication failed"
            default:
                return "Unknown error \(status)"
        }
    }

    var pluginError: PluginError {
        switch status {
        case errSecItemNotFound:
            return PluginError.BIOMETRIC_SECRET_NOT_FOUND
        case errSecUserCanceled:
            return PluginError.BIOMETRIC_DISMISSED
        case errSecAuthFailed:
                return PluginError.BIOMETRIC_AUTHENTICATION_FAILED
        default:
            return PluginError.BIOMETRIC_UNKNOWN_ERROR
        }
    }
}

class Secret {

    private static let keyName: String = "__homecaregps_secret_key"

    private func getBioSecAccessControl(invalidateOnEnrollment: Bool) -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?

        if #available(iOS 11.3, *) {
            access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                invalidateOnEnrollment ? .biometryCurrentSet : .userPresence,
                &error)
        } else {
            access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                invalidateOnEnrollment ? .touchIDCurrentSet : .userPresence,
                &error)
        }
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }

    func save(prompt: String, invalidateOnEnrollment: Bool, secret: Data) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: Secret.keyName,
                                    kSecValueData as String: secret,
                                    kSecAttrAccessControl as String: getBioSecAccessControl(invalidateOnEnrollment: invalidateOnEnrollment),
                                    kSecUseOperationPrompt as String: prompt]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    func load(prompt: String, invalidateOnEnrollment: Bool) throws -> Data {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: Secret.keyName,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnData as String: kCFBooleanTrue!,
                                    kSecAttrAccessControl as String: getBioSecAccessControl(invalidateOnEnrollment: invalidateOnEnrollment),
                                    kSecUseOperationPrompt as String: prompt]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { throw KeychainError(status: status) }

        guard let passwordData = item as? Data else { throw KeychainError(status: errSecInternalError) }
        return passwordData
    }

    func delete() throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: Secret.keyName]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }
}
