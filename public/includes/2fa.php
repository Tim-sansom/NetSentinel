<?php
/**
 * Lightweight TOTP 2FA Implementation
 * Generates and verifies Time-based One-Time Passwords (TOTP)
 * for secure admin authentication without external dependencies.
 * 
 * Compliant with RFC 6238 (TOTP) using HMAC-SHA1.
 */
class LightweightTOTP {
    // Standard TOTP configuration
    private const SECRET_LENGTH = 16; // 16 bytes = 128 bits of entropy
    private const TIME_STEP = 30;     // 30-second window (Standard)

    /**
     * Generates a cryptographically secure random secret key.
     * @return string Base32 encoded secret
     */
    public static function generateSecret() {
        // SECURITY: random_bytes() is cryptographically secure, unlike rand() or mt_rand()
        $bytes = random_bytes(self::SECRET_LENGTH);
        return self::base32Encode($bytes);
    }

    /**
     * Verifies a user-submitted TOTP code against the secret.
     * 
     * @param string $secret The user's stored secret
     * @param string $code The 6-digit code entered by the user
     * @param int $discrepancy Allowable time drift (default 1 step = +/- 30 seconds)
     * @return bool True if the code is valid
     */
    public static function verifyCode($secret, $code, $discrepancy = 1) {
        $code = str_pad($code, 6, '0', STR_PAD_LEFT);
        $currentTimeSlice = floor(time() / self::TIME_STEP);

        // Check the current time step and surrounding steps to account for clock drift
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = self::getCode($secret, $currentTimeSlice + $i);
            
            // SECURITY: hash_equals() prevents Timing Attacks. 
            // Standard '==' stops comparing at the first mismatch, leaking info about the correct code.
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generates the otpauth:// URI for QR code generation.
     */
    public static function getQRCodeUrl($issuer, $accountName, $secret) {
        $encodedIssuer = rawurlencode($issuer);
        $encodedAccount = rawurlencode($accountName);
        return "otpauth://totp/{$encodedIssuer}:{$encodedAccount}?secret={$secret}&issuer={$encodedIssuer}&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Core TOTP Algorithm: HMAC-SHA1 -> Dynamic Truncation -> Modulo 10^6
     */
    private static function getCode($secret, $timeSlice) {
        $secretKey = self::base32Decode($secret);
        
        // Pack time into 8-byte big-endian binary string
        $timePacked = pack('N*', 0) . pack('N*', $timeSlice);
        
        // Generate HMAC-SHA1 hash
        $hash = hash_hmac('SHA1', $timePacked, $secretKey, true);
        
        // Dynamic Truncation (RFC 4226 Section 5.3)
        $offset = ord(substr($hash, -1)) & 0x0F;
        $hashPart = substr($hash, $offset, 4);
        $value = unpack('N', $hashPart)[1];
        $value = $value & 0x7FFFFFFF; // Clear the most significant bit
        
        $modulo = pow(10, 6);
        return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
    }

    // --- Base32 Encoding/Decoding Helpers (Required for TOTP secrets) ---
    private static function base32Encode($data) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = '';
        $v = 0; $vBits = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $v = ($v << 8) | ord($data[$i]);
            $vBits += 8;
            while ($vBits >= 5) {
                $vBits -= 5;
                $result .= $chars[($v >> $vBits) & 31];
            }
        }
        if ($vBits > 0) {
            $result .= $chars[($v << (5 - $vBits)) & 31];
        }
        return $result;
    }

    private static function base32Decode($base32String) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = '';
        $v = 0; $vBits = 0;
        $base32String = strtoupper(rtrim($base32String, '='));
        for ($i = 0; $i < strlen($base32String); $i++) {
            $index = strpos($chars, $base32String[$i]);
            if ($index === false) continue;
            $v = ($v << 5) | $index;
            $vBits += 5;
            if ($vBits >= 8) {
                $vBits -= 8;
                $data .= chr(($v >> $vBits) & 0xFF);
            }
        }
        return $data;
    }
}
?>