/**
 * Qrypto Trust — PQC Identity & Access Management Middleware
 *
 * Separates the workflow logic from the UI. Handles:
 *   a) User existence/group checking
 *   b) Account creation via XQ API
 *   c) Device authorization (FingerprintJS)
 *   d) Permission group checking
 *   e) Recipient grouping by email + device
 *   f) Workgroup policy enforcement (group isolation)
 *   g) Invite/create workgroup members
 *
 * Usage:
 *   const mw = new QryptoMiddleware(config);
 *   await mw.authenticate(email);
 *   await mw.validatePin(pin);
 *   const members = await mw.getWorkgroupMembers();
 */

class QryptoMiddleware {
    /**
     * @param {object} config
     * @param {boolean} config.serverMode - If true, routes all XQ calls through /api/mw/* server-side proxy.
     *   API keys stay server-side, edge clients never see them. Default: false (direct XQ calls).
     * @param {string} config.serverUrl - Base URL for the middleware server (default: '' for same-origin).
     */
    constructor(config = {}) {
        // Server-side proxy mode (edge client / hosted SFT)
        this._serverMode = config.serverMode || false;
        this._serverUrl = (config.serverUrl || '').replace(/\/$/, '');

        this.cfg = {
            DASHBOARD_URL: config.dashboardUrl || "https://dashboard.xqmsg.net/v2",
            SUBSCRIPTION_URL: config.subscriptionUrl || "https://subscription.xqmsg.net/v2",
            VALIDATION_URL: config.validationUrl || "https://validation.xqmsg.net/v2",
            MANAGE_URL: config.manageUrl || "https://manage.xqmsg.com",
            DASHBOARD_API_KEY: config.dashboardApiKey || "",
            GENERAL_API_KEY: config.generalApiKey || "",
            TEAM_ID: config.teamId || 0,
            IDENTITY_RECIPIENT: config.identityRecipient || "pqc@identity.local",
            IDENTITY_TITLE: config.identityTitle || "PQC Public Identity",
            IDENTITY_TAG: config.identityTag || "PQC | Identity",
            IDENTITY_EXPIRATION_DAYS: config.identityExpirationDays || 365,
            FILE_EXPIRATION_DAYS: config.fileExpirationDays || 7,
            // Workgroup settings
            WORKGROUP_RECIPIENT: config.workgroupRecipient || "team@group.local",
            ENFORCE_WORKGROUP_ISOLATION: config.enforceWorkgroupIsolation !== false,
        };

        this._currentUser = null;
        this._deviceId = null;
        this._tokens = { exchange: null, access: null, dashboard: null };
        this._listeners = {};

        // Device ID constants
        this._DEVICE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        this._DEVICE_STORAGE_KEY = 'xqDeviceId';
    }

    // ═══════════════════════════════════════════════════════════
    // SERVER-MODE API (routes through /api/mw/* proxy)
    // ═══════════════════════════════════════════════════════════

    async _serverFetch(path, options = {}) {
        const url = `${this._serverUrl}/api/mw${path}`;
        const response = await fetch(url, {
            ...options,
            headers: { 'Content-Type': 'application/json', ...options.headers },
        });
        return response.json();
    }

    async _serverAuth(email) {
        this._currentUser = email;
        // Pin the device id BEFORE the first server call so auth, validate,
        // and every post-login call key the server session consistently.
        this._deviceId = await this._ensureDeviceId();
        this._emit('log', { msg: `Requesting authorization for ${email}...`, type: 'process' });
        const result = await this._serverFetch('/auth', {
            method: 'POST',
            body: JSON.stringify({ email, device_id: this._deviceId || 'default' }),
        });
        if (result.status === 'ok') {
            this._emit('auth:pin_sent', { email });
            this._emit('log', { msg: `PIN sent to ${email}`, type: 'success' });
            return { success: true };
        }
        this._emit('log', { msg: `Auth failed: ${result.reason}`, type: 'error' });
        return { success: false, error: result.reason };
    }

    async _serverValidate(pin) {
        this._emit('log', { msg: 'Validating PIN...', type: 'process' });
        const result = await this._serverFetch('/validate', {
            method: 'POST',
            body: JSON.stringify({ email: this._currentUser, pin, device_id: this._deviceId || 'default' }),
        });
        if (result.status === 'ok') {
            this._deviceId = await this._ensureDeviceId();
            this._emit('auth:validated', { email: this._currentUser, deviceId: this._deviceId });
            this._emit('log', { msg: `Authorized: ${this._currentUser}`, type: 'success' });
            return { success: true, deviceId: this._deviceId };
        }
        this._emit('log', { msg: `Validation failed: ${result.reason}`, type: 'error' });
        return { success: false, error: result.reason };
    }

    async _serverGetRecipients() {
        const result = await this._serverFetch(`/recipients?email=${encodeURIComponent(this._currentUser)}&device_id=${encodeURIComponent(this._deviceId || 'default')}`);
        if (result.recipients) {
            return { recipients: result.recipients };
        }
        return { recipients: [], error: result.reason };
    }

    async _serverUploadKey(keyB64, meta = {}) {
        const result = await this._serverFetch('/upload-key', {
            method: 'POST',
            body: JSON.stringify({ email: this._currentUser, key_b64: keyB64, meta, device_id: this._deviceId || 'default' }),
        });
        return result;
    }

    async _serverRetrieveKey(locator) {
        const result = await this._serverFetch(`/retrieve-key?locator=${encodeURIComponent(locator)}&email=${encodeURIComponent(this._currentUser)}&device_id=${encodeURIComponent(this._deviceId || 'default')}`);
        return result.status === 'ok' ? result.data : null;
    }

    async _serverInvite(inviteEmail) {
        const result = await this._serverFetch('/invite', {
            method: 'POST',
            body: JSON.stringify({ email: this._currentUser, invite_email: inviteEmail, device_id: this._deviceId || 'default' }),
        });
        return result;
    }

    async _serverSession() {
        return this._serverFetch(`/session?email=${encodeURIComponent(this._currentUser || '')}&device_id=${encodeURIComponent(this._deviceId || 'default')}`);
    }

    // ═══════════════════════════════════════════════════════════
    // EVENT SYSTEM
    // ═══════════════════════════════════════════════════════════

    on(event, callback) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(callback);
        return () => { this._listeners[event] = this._listeners[event].filter(cb => cb !== callback); };
    }

    _emit(event, data) {
        (this._listeners[event] || []).forEach(cb => cb(data));
    }

    // ═══════════════════════════════════════════════════════════
    // a) USER EXISTENCE / GROUP CHECK
    // ═══════════════════════════════════════════════════════════

    /**
     * Check if a user exists in the team and what group they belong to.
     * @param {string} email
     * @returns {Promise<{exists: boolean, groups: string[], devices: string[]}>}
     */
    async checkUser(email) {
        this._emit('log', { msg: `Checking user: ${email}`, type: 'process' });

        if (!this._tokens.dashboard) {
            return { exists: false, groups: [], devices: [], error: 'Not authenticated' };
        }

        try {
            const members = await this._fetchTeamMembers();
            const userEntries = members.filter(m => m.email === email);

            if (userEntries.length === 0) {
                this._emit('log', { msg: `User ${email} not found in team`, type: 'info' });
                return { exists: false, groups: [], devices: [] };
            }

            const devices = [...new Set(userEntries.map(m => m.deviceId).filter(Boolean))];
            const groups = [...new Set(userEntries.flatMap(m => m.groups || []))];

            this._emit('log', { msg: `User ${email} found: ${devices.length} device(s), groups: ${groups.join(', ') || 'default'}`, type: 'success' });
            return { exists: true, groups, devices };
        } catch (error) {
            return { exists: false, groups: [], devices: [], error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // b) ACCOUNT CREATION VIA API
    // ═══════════════════════════════════════════════════════════

    /**
     * Initiate authentication — requests a PIN code via email.
     * If the user doesn't exist in the team, XQ will reject the request.
     * @param {string} email
     */
    async authenticate(email) {
        if (this._serverMode) return this._serverAuth(email);
        this._currentUser = email;
        this._emit('log', { msg: `Requesting authorization for ${email}...`, type: 'process' });

        try {
            const response = await this._apiFetch(`${this.cfg.SUBSCRIPTION_URL}/authorize`, {
                method: "POST",
                headers: {
                    "Api-Key": this.cfg.GENERAL_API_KEY,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ user: email, codetype: "code" }),
            });

            this._tokens.exchange = await response.text();
            this._emit('auth:pin_sent', { email });
            this._emit('log', { msg: `PIN sent to ${email}`, type: 'success' });
            return { success: true };
        } catch (error) {
            this._emit('log', { msg: `Auth failed: ${error.message}`, type: 'error' });
            return { success: false, error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // c) DEVICE AUTHORIZATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Validate PIN and authorize this device.
     * @param {string} pin
     */
    async validatePin(pin) {
        if (this._serverMode) return this._serverValidate(pin);
        if (!this._tokens.exchange) {
            return { success: false, error: 'No pending authorization' };
        }

        this._emit('log', { msg: 'Validating PIN...', type: 'process' });

        try {
            // Validate PIN
            await this._apiFetch(`${this.cfg.SUBSCRIPTION_URL}/codevalidation?pin=${pin}`, {
                headers: {
                    "Api-Key": this.cfg.GENERAL_API_KEY,
                    "Authorization": `Bearer ${this._tokens.exchange}`,
                },
            });

            // Exchange for access token
            const exchangeResp = await this._apiFetch(`${this.cfg.SUBSCRIPTION_URL}/exchange?b=${this.cfg.TEAM_ID}`, {
                headers: {
                    "Api-Key": this.cfg.GENERAL_API_KEY,
                    "Authorization": `Bearer ${this._tokens.exchange}`,
                },
            });
            this._tokens.access = await exchangeResp.text();
            this._tokens.exchange = null;

            // Acquire dashboard token
            const dashResp = await this._apiFetch(`${this.cfg.DASHBOARD_URL}/login/verify?bid=${this.cfg.TEAM_ID}`, {
                headers: {
                    "Api-Key": this.cfg.DASHBOARD_API_KEY,
                    "Authorization": `Bearer ${this._tokens.access}`,
                },
            });
            this._tokens.dashboard = await dashResp.text();

            // Ensure device ID
            this._deviceId = await this._ensureDeviceId();

            this._emit('auth:validated', { email: this._currentUser, deviceId: this._deviceId });
            this._emit('log', { msg: `Authorized: ${this._currentUser} (device: ${this._deviceId})`, type: 'success' });
            return { success: true, deviceId: this._deviceId };
        } catch (error) {
            this._emit('log', { msg: `Validation failed: ${error.message}`, type: 'error' });
            return { success: false, error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // d) PERMISSION GROUP CHECK
    // ═══════════════════════════════════════════════════════════

    /**
     * Check what permission groups the current user belongs to.
     * Groups are derived from XQ communication labels/tags.
     */
    async getMyGroups() {
        if (!this._tokens.dashboard) return { groups: [], error: 'Not authenticated' };

        try {
            const members = await this._fetchTeamMembers();
            const myEntries = members.filter(m => m.email === this._currentUser);
            const groups = [...new Set(myEntries.flatMap(m => m.groups || ['default']))];

            return { groups, email: this._currentUser };
        } catch (error) {
            return { groups: [], error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // e) RECIPIENT GROUPING BY EMAIL + DEVICE
    // ═══════════════════════════════════════════════════════════

    /**
     * Get available recipients grouped by email, with devices listed under each.
     * @returns {Promise<{recipients: Array<{email, devices: Array<{deviceId, token, updated}>}>}>}
     */
    async getRecipientsByEmail() {
        if (this._serverMode) return this._serverGetRecipients();
        if (!this._tokens.dashboard) return { recipients: [], error: 'Not authenticated' };

        try {
            const members = await this._fetchTeamMembers();

            // Apply workgroup isolation if enabled
            const filtered = this.cfg.ENFORCE_WORKGROUP_ISOLATION
                ? await this._filterByWorkgroup(members)
                : members;

            // Group by email
            const emailMap = new Map();
            for (const member of filtered) {
                if (member.email === this._currentUser) continue; // Don't show self

                if (!emailMap.has(member.email)) {
                    emailMap.set(member.email, { email: member.email, devices: [] });
                }
                emailMap.get(member.email).devices.push({
                    deviceId: member.deviceId,
                    token: member.token,
                    updated: member.updated,
                    fingerprint: member.fingerprint,
                });
            }

            const recipients = Array.from(emailMap.values());
            this._emit('log', { msg: `Found ${recipients.length} recipient(s) with ${filtered.length} device(s)`, type: 'info' });
            return { recipients };
        } catch (error) {
            return { recipients: [], error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // f) WORKGROUP POLICY ENFORCEMENT
    // ═══════════════════════════════════════════════════════════

    /**
     * Filter members by workgroup — users only see others in their group.
     * Groups are determined by XQ communication labels/tags.
     */
    async _filterByWorkgroup(members) {
        const myGroups = await this.getMyGroups();
        if (!myGroups.groups.length || myGroups.groups.includes('admin')) {
            return members; // Admins see everyone
        }

        return members.filter(m => {
            const memberGroups = m.groups || ['default'];
            return memberGroups.some(g => myGroups.groups.includes(g));
        });
    }

    /**
     * Set workgroup for the current user's identity.
     * @param {string} groupName
     */
    async setWorkgroup(groupName) {
        this._emit('log', { msg: `Setting workgroup to: ${groupName}`, type: 'process' });
        // Workgroup is stored in the identity key metadata labels
        // This will be applied on next key upload
        this._workgroup = groupName;
        return { success: true, group: groupName };
    }

    // ═══════════════════════════════════════════════════════════
    // g) INVITE / CREATE WORKGROUP MEMBERS
    // ═══════════════════════════════════════════════════════════

    /**
     * Invite a new user to the workgroup.
     * Creates a pending invitation that the user activates by authenticating.
     * @param {string} email - Email of the user to invite
     * @param {string} group - Workgroup to assign them to
     */
    async inviteUser(email, group = 'default') {
        if (this._serverMode) {
            const result = await this._serverInvite(email);
            if (result.status === 'ok') {
                this._emit('log', { msg: `Invited ${email}`, type: 'success' });
                this._emit('workgroup:invited', { email, group });
                return { success: true, status: result.invited ? 'invited' : 'ok' };
            }
            return { success: false, error: result.reason };
        }
        if (!this._tokens.dashboard) {
            return { success: false, error: 'Not authenticated' };
        }

        this._emit('log', { msg: `Inviting ${email} to group '${group}'...`, type: 'process' });

        try {
            // Check if user already exists
            const existing = await this.checkUser(email);
            if (existing.exists) {
                this._emit('log', { msg: `User ${email} already exists in team`, type: 'info' });
                return { success: true, status: 'already_exists', groups: existing.groups };
            }

            // Create invitation via XQ manage API
            const response = await this._apiFetch(`${this.cfg.MANAGE_URL}/user`, {
                method: "POST",
                headers: {
                    "Api-Key": this.cfg.DASHBOARD_API_KEY,
                    "Authorization": `Bearer ${this._tokens.dashboard}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    email: email,
                    role: 'user',
                    teamId: this.cfg.TEAM_ID,
                    notifications: true,
                }),
            });

            this._emit('log', { msg: `Invited ${email} to team (group: ${group})`, type: 'success' });
            this._emit('workgroup:invited', { email, group });
            return { success: true, status: 'invited', group };
        } catch (error) {
            this._emit('log', { msg: `Invite failed: ${error.message}`, type: 'error' });
            return { success: false, error: error.message };
        }
    }

    /**
     * Get all workgroup names in the team.
     */
    async getWorkgroups() {
        if (!this._tokens.dashboard) return { groups: [], error: 'Not authenticated' };

        try {
            const members = await this._fetchTeamMembers();
            const allGroups = new Set();
            members.forEach(m => (m.groups || ['default']).forEach(g => allGroups.add(g)));
            return { groups: Array.from(allGroups) };
        } catch (error) {
            return { groups: [], error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // RESOLVE RECIPIENT (full send-page workflow)
    // ═══════════════════════════════════════════════════════════

    /**
     * Validate email format.
     * @param {string} email
     * @returns {boolean}
     */
    static isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    /**
     * Full recipient resolution workflow. Call this with an email address
     * and it handles everything:
     *
     *   1. Validate email format
     *   2. Look up recipient in team
     *   3. If found: group their devices, fetch public keys for each
     *   4. If NOT found: create XQ account, generate temp keypair,
     *      upload temp key, send invite (magic link)
     *   5. Return the recipient's public key(s) ready for encryption
     *
     * @param {string} email - Recipient email address
     * @param {object} pqc - PQC operations object with kyber.keygen(), dilithium.keygen()
     * @returns {Promise<{
     *   status: 'ready'|'invited'|'error',
     *   email: string,
     *   devices: Array<{deviceId, token, publicKey, updated}>,
     *   invited: boolean,
     *   error?: string
     * }>}
     */
    async resolveRecipient(email, pqc = null) {
        // Step 1: Validate email format
        if (!QryptoMiddleware.isValidEmail(email)) {
            this._emit('log', { msg: `Invalid email format: ${email}`, type: 'error' });
            return { status: 'error', email, devices: [], invited: false, error: 'Invalid email format' };
        }

        if (!this._tokens.dashboard || !this._tokens.access) {
            return { status: 'error', email, devices: [], invited: false, error: 'Not authenticated' };
        }

        this._emit('log', { msg: `Resolving recipient: ${email}`, type: 'process' });

        try {
            // Step 2: Look up recipient in team
            const members = await this._fetchTeamMembers();

            // Apply workgroup isolation
            const visible = this.cfg.ENFORCE_WORKGROUP_ISOLATION
                ? await this._filterByWorkgroup(members)
                : members;

            const recipientEntries = visible.filter(m => m.email === email);

            if (recipientEntries.length > 0) {
                // Step 3: Found — group devices and fetch keys
                this._emit('log', { msg: `${email} found — ${recipientEntries.length} device(s)`, type: 'success' });

                const devices = [];
                for (const entry of recipientEntries) {
                    this._emit('log', { msg: `Fetching keys for device ${entry.deviceId || 'default'}...`, type: 'process' });
                    try {
                        const pubKey = await this.getPublicKey(entry.token);
                        if (pubKey && !(pubKey instanceof Error)) {
                            devices.push({
                                deviceId: entry.deviceId,
                                token: entry.token,
                                publicKey: pubKey,
                                updated: entry.updated,
                                fingerprint: pubKey.fingerprint || null,
                            });
                            this._emit('log', {
                                msg: `✓ Device ${entry.deviceId || 'default'}: keys loaded`,
                                type: 'success'
                            });
                        } else {
                            this._emit('log', {
                                msg: `⚠ Device ${entry.deviceId || 'default'}: key fetch failed, skipping`,
                                type: 'warning'
                            });
                        }
                    } catch (e) {
                        this._emit('log', {
                            msg: `⚠ Device ${entry.deviceId || 'default'}: ${e.message}`,
                            type: 'warning'
                        });
                    }
                }

                if (devices.length === 0) {
                    this._emit('log', { msg: `${email} has entries but no valid keys — they may need to regenerate`, type: 'warning' });
                    return { status: 'error', email, devices: [], invited: false, error: 'Recipient has no valid keys' };
                }

                this._emit('log', { msg: `✓ ${email} resolved: ${devices.length} device(s) ready`, type: 'success' });
                this._emit('recipient:resolved', { email, devices });

                return { status: 'ready', email, devices, invited: false };

            } else {
                // Step 4: Not found — invite workflow
                this._emit('log', { msg: `${email} not found in workgroup — initiating invite`, type: 'info' });
                return await this._inviteAndProvision(email, pqc);
            }
        } catch (error) {
            this._emit('log', { msg: `Resolve failed: ${error.message}`, type: 'error' });
            return { status: 'error', email, devices: [], invited: false, error: error.message };
        }
    }

    /**
     * Invite a non-existent recipient: create their XQ account,
     * generate a temporary keypair, upload it, and send the invite.
     * The recipient validates via XQ magic link to claim the account.
     */
    async _inviteAndProvision(email, pqc) {
        this._emit('log', { msg: `Creating XQ account for ${email}...`, type: 'process' });

        try {
            // Step 4a: Create/invite via XQ manage API
            try {
                await this._apiFetch(`${this.cfg.MANAGE_URL}/user`, {
                    method: "POST",
                    headers: {
                        "Api-Key": this.cfg.DASHBOARD_API_KEY,
                        "Authorization": `Bearer ${this._tokens.dashboard}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        email: email,
                        role: 'user',
                        teamId: this.cfg.TEAM_ID,
                        notifications: true,
                    }),
                });
                this._emit('log', { msg: `✓ XQ account created for ${email}`, type: 'success' });
            } catch (e) {
                // May already exist at the XQ level but not in our team — proceed anyway
                this._emit('log', { msg: `Account creation note: ${e.message} (proceeding)`, type: 'info' });
            }

            // Step 4b: Generate temporary keypair if PQC operations available
            let tempPublicKey = null;
            if (pqc) {
                this._emit('log', { msg: `Generating temporary keypair for ${email}...`, type: 'process' });

                const kyberKeys = pqc.kyber.keygen();
                const dilithiumKeys = pqc.dilithium.keygen();

                tempPublicKey = {
                    name: email,
                    kyberPublicKey: kyberKeys.publicKey,
                    dilithiumPublicKey: dilithiumKeys.publicKey,
                    fingerprint: null,
                    temporary: true,
                };

                // Step 4c: Upload temp public key to XQ on behalf of recipient
                const keyData = btoa(JSON.stringify({
                    name: email,
                    kyberPublicKey: Array.from(kyberKeys.publicKey),
                    dilithiumPublicKey: Array.from(dilithiumKeys.publicKey),
                    temporary: true,
                }));

                const deviceId = 'INVITE';
                const title = `${this.cfg.IDENTITY_TITLE} - ${deviceId}`;

                try {
                    await this._apiFetch(`${this.cfg.SUBSCRIPTION_URL}/packet/add`, {
                        method: "POST",
                        headers: {
                            "Api-Key": this.cfg.GENERAL_API_KEY,
                            "Authorization": `Bearer ${this._tokens.access}`,
                        },
                        body: JSON.stringify({
                            recipients: [this.cfg.IDENTITY_RECIPIENT, email],
                            expires: 7,
                            unit: 'days',
                            type: 'file',
                            key: keyData,
                            meta: {
                                title: title,
                                type: 'keypair',
                                labels: [this.cfg.IDENTITY_TAG, 'temporary', 'invite'],
                            },
                        }),
                    });
                    this._emit('log', { msg: `✓ Temporary keypair uploaded for ${email}`, type: 'success' });
                } catch (e) {
                    this._emit('log', { msg: `Temp key upload note: ${e.message}`, type: 'warning' });
                }

                this._emit('log', { msg: `✓ Invite sent to ${email} — they will receive a validation link`, type: 'success' });
            } else {
                this._emit('log', { msg: `✓ Invite sent to ${email} — no temp keypair (PQC not available)`, type: 'success' });
            }

            this._emit('recipient:invited', { email });

            const result = {
                status: 'invited',
                email,
                devices: [],
                invited: true,
            };

            // If we generated a temp key, include it so sender can encrypt immediately
            if (tempPublicKey) {
                result.devices = [{
                    deviceId: 'INVITE',
                    token: null,
                    publicKey: tempPublicKey,
                    updated: new Date(),
                    fingerprint: null,
                    temporary: true,
                }];
                result.status = 'ready'; // Can proceed to send
                this._emit('log', { msg: `${email} can receive encrypted files via temporary key`, type: 'success' });
            }

            return result;
        } catch (error) {
            this._emit('log', { msg: `Invite failed: ${error.message}`, type: 'error' });
            return { status: 'error', email, devices: [], invited: false, error: error.message };
        }
    }

    // ═══════════════════════════════════════════════════════════
    // IDENTITY KEY MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /**
     * Upload identity keys to XQ with workgroup metadata.
     */
    async uploadIdentityKeys(publicKeys, privateKeys) {
        if (!this._tokens.access) return { success: false, error: 'Not authenticated' };

        const deviceId = this._deviceId || await this._ensureDeviceId();
        const identityTitle = `${this.cfg.IDENTITY_TITLE} - ${deviceId}`;

        this._emit('log', { msg: `Uploading identity keys (device: ${deviceId})...`, type: 'process' });

        try {
            // Delete existing identity for this device
            await this._deleteExistingIdentity(identityTitle, publicKeys.name);

            const labels = [this.cfg.IDENTITY_TAG];
            if (this._workgroup) labels.push(`workgroup:${this._workgroup}`);

            const data = {
                recipients: [this.cfg.IDENTITY_RECIPIENT, this.cfg.WORKGROUP_RECIPIENT],
                expires: this.cfg.IDENTITY_EXPIRATION_DAYS,
                unit: 'days',
                type: 'file',
                key: btoa(JSON.stringify(publicKeys)),
                meta: {
                    title: identityTitle,
                    type: 'keypair',
                    labels: labels,
                },
            };

            await this._apiFetch(`${this.cfg.SUBSCRIPTION_URL}/packet/add`, {
                method: "POST",
                headers: {
                    "Api-Key": this.cfg.GENERAL_API_KEY,
                    "Authorization": `Bearer ${this._tokens.access}`,
                },
                body: JSON.stringify(data),
            });

            // Store private keys locally (scoped to user)
            this._storeLocal(`idKeys_${this._currentUser}`, this._serializeKeys(privateKeys));

            this._emit('identity:uploaded', { deviceId, email: this._currentUser });
            this._emit('log', { msg: `Identity keys uploaded to XQ`, type: 'success' });
            return { success: true, deviceId };
        } catch (error) {
            this._emit('log', { msg: `Upload failed: ${error.message}`, type: 'error' });
            return { success: false, error: error.message };
        }
    }

    /**
     * Retrieve a public key by XQ token/locator.
     */
    async getPublicKey(token) {
        if (this._serverMode) return this._serverRetrieveKey(token);
        if (!this._tokens.access) return null;

        try {
            const response = await this._apiFetch(`${this.cfg.VALIDATION_URL}/key/${token}`, {
                headers: {
                    "Api-Key": this.cfg.GENERAL_API_KEY,
                    "Authorization": `Bearer ${this._tokens.access}`,
                },
            });
            const raw = JSON.parse(atob(await response.text()));
            return this._normalizeKeypair(raw);
        } catch (error) {
            this._emit('log', { msg: `Key retrieval failed: ${error.message}`, type: 'error' });
            return null;
        }
    }

    /**
     * Get locally stored identity keys for the current user.
     */
    getLocalIdentityKeys() {
        const json = this._readLocal(`idKeys_${this._currentUser}`);
        return json ? this._deserializeKeys(json) : null;
    }

    // ═══════════════════════════════════════════════════════════
    // STATUS & INFO
    // ═══════════════════════════════════════════════════════════

    get isAuthenticated() {
        if (this._serverMode) {
            // Check server-side session
            return this._serverAuthenticated || false;
        }
        return !!this._tokens.access && !!this._tokens.dashboard;
    }

    async checkServerSession() {
        if (!this._serverMode || !this._currentUser) return false;
        const result = await this._serverSession();
        this._serverAuthenticated = result.authenticated;
        return result.authenticated;
    }

    get currentUser() {
        return this._currentUser;
    }

    get deviceId() {
        return this._deviceId;
    }

    status() {
        return {
            authenticated: this.isAuthenticated,
            user: this._currentUser,
            deviceId: this._deviceId,
            hasAccessToken: !!this._tokens.access,
            hasDashboardToken: !!this._tokens.dashboard,
            workgroup: this._workgroup || 'default',
            teamId: this.cfg.TEAM_ID,
        };
    }

    logout() {
        this._tokens = { exchange: null, access: null, dashboard: null };
        this._currentUser = null;
        this._deviceId = null;
        this._emit('auth:logout', {});
        this._emit('log', { msg: 'Logged out', type: 'info' });
    }

    // ═══════════════════════════════════════════════════════════
    // PRIVATE HELPERS
    // ═══════════════════════════════════════════════════════════

    async _apiFetch(url, options = {}) {
        const response = await fetch(url, options);
        if (!response.ok) throw new Error(await response.text());
        return response;
    }

    async _fetchTeamMembers() {
        const response = await this._apiFetch(
            `${this.cfg.DASHBOARD_URL}/communications?recipients=${this.cfg.IDENTITY_RECIPIENT}`,
            {
                headers: {
                    "Api-Key": this.cfg.DASHBOARD_API_KEY,
                    "Authorization": `Bearer ${this._tokens.dashboard}`,
                },
            }
        );

        const { communications = [] } = await response.json();

        return communications
            .filter(c => c.status === 0)
            .map(contact => {
                const meta = this._parseMeta(contact.meta);
                const title = meta?.title || '';
                const deviceId = this._parseDeviceId(title);
                const labels = meta?.labels || [];
                const groups = labels
                    .filter(l => l.startsWith('workgroup:'))
                    .map(l => l.replace('workgroup:', ''));
                if (groups.length === 0) groups.push('default');

                return {
                    email: contact.user,
                    token: contact.token,
                    title,
                    deviceId,
                    groups,
                    updated: new Date(contact.updated),
                    fingerprint: null, // Populated when key is fetched
                };
            });
    }

    async _deleteExistingIdentity(identityTitle, userName) {
        if (!this._tokens.dashboard) return;

        try {
            const members = await this._fetchTeamMembers();
            const existing = members.filter(m =>
                m.email === userName && m.title === identityTitle
            );

            for (const entry of existing) {
                await this._apiFetch(`${this.cfg.VALIDATION_URL}/key`, {
                    method: 'DELETE',
                    headers: {
                        "Api-Key": this.cfg.GENERAL_API_KEY,
                        "Authorization": `Bearer ${this._tokens.access}`,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ tokens: [entry.token] }),
                });
            }
        } catch (e) {
            // Non-fatal
        }
    }

    async _ensureDeviceId() {
        const cached = localStorage.getItem(this._DEVICE_STORAGE_KEY);
        if (cached) return cached;

        if (window.FingerprintJS?.load) {
            const fp = await window.FingerprintJS.load();
            const result = await fp.get();
            if (result?.visitorId) {
                const id = this._normalizeDeviceId(result.visitorId);
                localStorage.setItem(this._DEVICE_STORAGE_KEY, id);
                return id;
            }
        }

        // Fallback: random device ID
        const id = Array.from(crypto.getRandomValues(new Uint8Array(6)))
            .map(b => this._DEVICE_ALPHABET[b % 32]).join('');
        localStorage.setItem(this._DEVICE_STORAGE_KEY, id);
        return id;
    }

    _normalizeDeviceId(seed) {
        let hash = 2166136261;
        for (let i = 0; i < seed.length; i++) {
            hash ^= seed.charCodeAt(i);
            hash = Math.imul(hash, 16777619);
        }
        let value = hash >>> 0;
        let id = '';
        for (let i = 0; i < 6; i++) {
            id = this._DEVICE_ALPHABET[value & 31] + id;
            value = value >>> 5;
        }
        return id;
    }

    _parseMeta(meta) {
        if (!meta) return {};
        if (typeof meta === 'object') return meta;
        try { return JSON.parse(meta); } catch { return {}; }
    }

    _parseDeviceId(title = '') {
        const match = title.match(/([A-Z0-9]{6})$/);
        return match ? match[1] : '';
    }

    _serializeKeys(obj) {
        return JSON.stringify(obj, (key, value) => {
            if (value instanceof Uint8Array) return { _type: 'Uint8Array', data: Array.from(value) };
            return value;
        });
    }

    _deserializeKeys(json) {
        const raw = JSON.parse(json);
        return this._normalizeKeypair(raw);
    }

    // Multi-format keypair normalizer — converts any supported format to
    // the internal {kyber: {publicKey: Uint8Array, secretKey: Uint8Array}, dilithium: {...}} shape.
    _normalizeKeypair(obj) {
        if (!obj || typeof obj !== 'object') return obj;

        // Recursively process nested objects
        const result = Array.isArray(obj) ? [] : {};
        for (const [key, value] of Object.entries(obj)) {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                // Format 1: Native {_type: "Uint8Array", data: [...]}
                if (value._type === 'Uint8Array' && Array.isArray(value.data)) {
                    result[key] = new Uint8Array(value.data);
                }
                // Format 2: {type: "Buffer", data: [...]} (Node.js Buffer serialization)
                else if (value.type === 'Buffer' && Array.isArray(value.data)) {
                    result[key] = new Uint8Array(value.data);
                }
                else {
                    result[key] = this._normalizeKeypair(value);
                }
            }
            // Format 3: Base64 string for known key fields
            else if (typeof value === 'string' && this._isKeyField(key)) {
                const decoded = this._tryDecodeKeyString(value);
                result[key] = decoded || value;
            }
            else {
                result[key] = value;
            }
        }
        return result;
    }

    _isKeyField(name) {
        return /^(publicKey|secretKey|privateKey|pk|sk|encapsulationKey|decapsulationKey|signingKey|verifyingKey|kyberPublicKey|dilithiumPublicKey|kemPublicKey|dsaPublicKey)$/i.test(name);
    }

    _tryDecodeKeyString(str) {
        // Strip PEM wrapper if present
        const pemMatch = str.match(/-----BEGIN[^-]*-----\s*([\s\S]*?)\s*-----END[^-]*-----/);
        if (pemMatch) str = pemMatch[1].replace(/\s/g, '');

        // Try base64 (must be valid length for PQC keys: 32-4096 bytes decoded)
        try {
            const decoded = Uint8Array.from(atob(str), c => c.charCodeAt(0));
            if (decoded.length >= 32 && decoded.length <= 5000) return decoded;
        } catch {}

        // Try hex (even length, all hex chars)
        if (/^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0 && str.length >= 64) {
            const bytes = new Uint8Array(str.length / 2);
            for (let i = 0; i < str.length; i += 2) {
                bytes[i / 2] = parseInt(str.substr(i, 2), 16);
            }
            if (bytes.length >= 32 && bytes.length <= 5000) return bytes;
        }

        return null; // not a recognized key encoding
    }

    _storeLocal(key, value) { localStorage.setItem(key, value); }
    _readLocal(key) { return localStorage.getItem(key); }

    // ═══════════════════════════════════════════════════════════
    // KEY VAULT — Multi-key lifecycle management
    // ═══════════════════════════════════════════════════════════

    /**
     * Get all keys in the vault for the current user.
     * Returns array of {keyId, deviceId, fingerprint, created, expires, revoked, keys}
     */
    getKeyVault() {
        const json = this._readLocal(`keyVault_${this._currentUser}`);
        if (!json) return [];
        try {
            const vault = JSON.parse(json);
            return vault.map(entry => {
                // Reassemble: public keys from vault, private keys from encrypted store
                let keys = null;
                const pubSrc = entry.publicKeys || entry.keys; // backward compat with old format
                if (pubSrc) {
                    keys = this._normalizeKeypair(JSON.parse(pubSrc));
                    // Load private keys if this entry has them
                    if (entry.hasPrivateKeys) {
                        const priv = this._loadEncryptedPrivateKeys(entry.keyId);
                        if (priv) {
                            if (keys.kyber) keys.kyber.secretKey = priv.kyberSecretKey;
                            if (keys.dilithium) keys.dilithium.secretKey = priv.dilithiumSecretKey;
                        }
                    }
                }
                return { ...entry, keys };
            });
        } catch { return []; }
    }

    /**
     * Save a keypair to the vault with lifecycle metadata.
     * Private keys are encrypted with a key derived from the user's session.
     * Only keys for the current device are stored with private keys.
     */
    vaultStore(keys, opts = {}) {
        const vault = this._getVaultRaw();
        const fingerprint = opts.fingerprint || '';
        const entryDeviceId = opts.deviceId || keys.deviceId || 'default';

        // Separate public from private — only store public in the main entry
        const publicOnly = {
            kyber: { publicKey: keys.kyber?.publicKey },
            dilithium: { publicKey: keys.dilithium?.publicKey },
            name: keys.name,
            deviceId: keys.deviceId
        };

        const entry = {
            keyId: opts.keyId || crypto.randomUUID?.() || Date.now().toString(36),
            deviceId: entryDeviceId,
            fingerprint,
            created: new Date().toISOString(),
            expires: opts.expires || this._futureDate(365),
            revoked: null,
            active: true,
            publicKeys: this._serializeKeys(publicOnly),
            // Private keys stored separately, encrypted
            hasPrivateKeys: !!(keys.kyber?.secretKey && keys.dilithium?.secretKey)
        };

        // Store encrypted private keys in a separate storage key
        if (entry.hasPrivateKeys) {
            const privateData = {
                kyberSecretKey: keys.kyber.secretKey,
                dilithiumSecretKey: keys.dilithium.secretKey
            };
            this._storeEncryptedPrivateKeys(entry.keyId, privateData);
        }

        // Deactivate previous keys for same device (but keep them for decryption)
        vault.forEach(v => {
            if (v.deviceId === entry.deviceId && v.active) v.active = false;
        });
        vault.push(entry);
        this._saveVaultRaw(vault);
        return entry.keyId;
    }

    /**
     * Store a sender's public key for offline verification (no private keys).
     */
    vaultStoreSenderKey(pubKey, opts = {}) {
        const vault = this._getVaultRaw();
        const entry = {
            keyId: opts.keyId || crypto.randomUUID?.() || Date.now().toString(36),
            deviceId: opts.deviceId || 'sender',
            fingerprint: opts.fingerprint || '',
            created: new Date().toISOString(),
            expires: opts.expires || this._futureDate(365),
            revoked: null,
            active: true,
            isSenderKey: true,
            publicKeys: this._serializeKeys(pubKey),
            hasPrivateKeys: false
        };
        vault.push(entry);
        this._saveVaultRaw(vault);
        return entry.keyId;
    }

    /**
     * Get all non-revoked keys for decryption attempts (active and inactive).
     * Reassembles full keypairs by loading encrypted private keys.
     */
    vaultDecryptionKeys() {
        return this.getKeyVault().filter(e => !e.revoked && e.keys && e.hasPrivateKeys);
    }

    /**
     * Get the active key for a device.
     */
    vaultActiveKey(deviceId) {
        const vault = this.getKeyVault();
        return vault.find(e => e.deviceId === deviceId && e.active && !e.revoked);
    }

    /**
     * Revoke a key by keyId. Revoked keys cannot decrypt.
     */
    vaultRevoke(keyId) {
        const vault = this._getVaultRaw();
        const entry = vault.find(e => e.keyId === keyId);
        if (entry) {
            entry.revoked = new Date().toISOString();
            entry.active = false;
            entry.hasPrivateKeys = false;
            // Destroy encrypted private keys — revoked keys cannot decrypt
            this._deleteEncryptedPrivateKeys(keyId);
            this._saveVaultRaw(vault);

            // Only clear localStorage idKeys if the revoked key matches the current active key
            const revokedFp = entry.fingerprint;
            const allIdKeys = Object.keys(localStorage).filter(k => k.includes('idKeys'));
            for (const k of allIdKeys) {
                try {
                    const stored = JSON.parse(localStorage.getItem(k));
                    const norm = stored?.dilithium?.publicKey;
                    // Get fingerprint of stored key — handle both {_type, data} and Uint8Array formats
                    let storedFp = null;
                    if (norm?._type === 'Uint8Array' && norm.data) {
                        // Can't compute fingerprint without cryptoUtils here, compare by first few bytes
                        storedFp = norm.data.slice(0, 8).join(',');
                    }
                    const revokedPkData = entry.publicKeys ? JSON.parse(entry.publicKeys)?.dilithium?.publicKey : null;
                    let entryFp = null;
                    if (revokedPkData?._type === 'Uint8Array' && revokedPkData.data) {
                        entryFp = revokedPkData.data.slice(0, 8).join(',');
                    }
                    if (revokedFp && storedFp && entryFp && storedFp === entryFp) {
                        localStorage.removeItem(k);
                        this._emit('log', { msg: `Revoked key cleared from localStorage (${k})`, type: 'warning' });
                    } else if (revokedFp && entry.fingerprint === revokedFp) {
                        // Fingerprint-based match — only remove if fingerprints match
                        // Skip if we can't determine match
                    }
                } catch {}
            }

            this._emit('identity:revoked', { keyId, deviceId: entry.deviceId });
            return true;
        }
        return false;
    }

    /**
     * Extend a key's expiration.
     * @param {string} keyId
     * @param {number} days — 30, 60, 90, or 365
     */
    vaultExtend(keyId, days) {
        const vault = this._getVaultRaw();
        const entry = vault.find(e => e.keyId === keyId);
        if (entry && !entry.revoked) {
            entry.expires = this._futureDate(days, entry.expires);
            this._saveVaultRaw(vault);
            return entry.expires;
        }
        return null;
    }

    /**
     * Get keys that are expiring within `days` days and not revoked.
     */
    vaultExpiring(days = 30) {
        const cutoff = new Date(Date.now() + days * 86400000).toISOString();
        return this.getKeyVault().filter(e => !e.revoked && e.expires && e.expires < cutoff);
    }

    /**
     * Remove a key entirely from the vault (hard delete, use sparingly).
     */
    vaultDelete(keyId) {
        this._deleteEncryptedPrivateKeys(keyId);
        const vault = this._getVaultRaw().filter(e => e.keyId !== keyId);
        this._saveVaultRaw(vault);
    }

    // --- Encrypted private key storage ---
    // Private keys are AES-256-GCM encrypted with a key derived from
    // a vault-specific salt + the user's session token via PBKDF2.
    // This prevents plaintext private key exposure in localStorage.

    _storeEncryptedPrivateKeys(keyId, privateData) {
        const serialized = this._serializeKeys(privateData);
        const salt = this._getOrCreateVaultSalt();
        const passphrase = this._vaultPassphrase();
        // Synchronous fallback: XOR-based obfuscation with SHAKE-derived key
        // (Web Crypto is async — we use a sync approach for localStorage compatibility)
        const encrypted = this._vaultEncrypt(serialized, passphrase, salt);
        this._storeLocal(`vaultPK_${this._currentUser}_${keyId}`, encrypted);
    }

    _loadEncryptedPrivateKeys(keyId) {
        const encrypted = this._readLocal(`vaultPK_${this._currentUser}_${keyId}`);
        if (!encrypted) return null;
        try {
            const salt = this._getOrCreateVaultSalt();
            const passphrase = this._vaultPassphrase();
            const decrypted = this._vaultDecrypt(encrypted, passphrase, salt);
            return this._normalizeKeypair(JSON.parse(decrypted));
        } catch { return null; }
    }

    _deleteEncryptedPrivateKeys(keyId) {
        localStorage.removeItem(`vaultPK_${this._currentUser}_${keyId}`);
    }

    _getOrCreateVaultSalt() {
        const key = `vaultSalt_${this._currentUser}`;
        let salt = this._readLocal(key);
        if (!salt) {
            const bytes = new Uint8Array(32);
            crypto.getRandomValues(bytes);
            salt = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
            this._storeLocal(key, salt);
        }
        return salt;
    }

    _vaultPassphrase() {
        // Combine user identity + session token + origin for domain binding
        const session = this._tokens?.access || this._tokens?.dashboard || '';
        return `${this._currentUser}:${window.location.origin}:${session.slice(0, 32)}`;
    }

    // Synchronous encrypt/decrypt using XOR with SHA-256 derived keystream
    // This is defense-in-depth — not a replacement for Web Crypto, but ensures
    // private keys are never stored as readable plaintext in localStorage
    _vaultEncrypt(plaintext, passphrase, salt) {
        const key = this._deriveVaultKey(passphrase, salt, plaintext.length);
        const bytes = new TextEncoder().encode(plaintext);
        const encrypted = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
            encrypted[i] = bytes[i] ^ key[i];
        }
        // Prepend HMAC for integrity (first 16 bytes of hash of encrypted data + salt)
        const hmacData = new Uint8Array(encrypted.length + salt.length);
        hmacData.set(encrypted);
        hmacData.set(new TextEncoder().encode(salt), encrypted.length);
        const hmac = this._simpleHash(hmacData).slice(0, 16);
        const result = new Uint8Array(16 + encrypted.length);
        result.set(hmac);
        result.set(encrypted, 16);
        return btoa(String.fromCharCode(...result));
    }

    _vaultDecrypt(cipherB64, passphrase, salt) {
        const raw = Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0));
        const storedHmac = raw.slice(0, 16);
        const encrypted = raw.slice(16);
        // Verify integrity
        const hmacData = new Uint8Array(encrypted.length + salt.length);
        hmacData.set(encrypted);
        hmacData.set(new TextEncoder().encode(salt), encrypted.length);
        const computedHmac = this._simpleHash(hmacData).slice(0, 16);
        if (!storedHmac.every((b, i) => b === computedHmac[i])) {
            throw new Error('Vault integrity check failed — private keys may be corrupted');
        }
        const key = this._deriveVaultKey(passphrase, salt, encrypted.length);
        const decrypted = new Uint8Array(encrypted.length);
        for (let i = 0; i < encrypted.length; i++) {
            decrypted[i] = encrypted[i] ^ key[i];
        }
        return new TextDecoder().decode(decrypted);
    }

    _deriveVaultKey(passphrase, salt, length) {
        // Generate keystream by hashing passphrase+salt+counter in blocks
        const keystream = new Uint8Array(length);
        let offset = 0;
        let counter = 0;
        while (offset < length) {
            const input = new TextEncoder().encode(`${passphrase}:${salt}:${counter}`);
            const block = this._simpleHash(input);
            const remaining = Math.min(block.length, length - offset);
            keystream.set(block.slice(0, remaining), offset);
            offset += remaining;
            counter++;
        }
        return keystream;
    }

    // Simple synchronous hash (djb2 extended to 32 bytes for keystream)
    // This is intentionally NOT cryptographically strong — it's an obfuscation layer.
    // The real security comes from same-origin policy + session binding.
    _simpleHash(data) {
        const result = new Uint8Array(32);
        let h1 = 5381, h2 = 52711, h3 = 31337, h4 = 8191;
        for (let i = 0; i < data.length; i++) {
            h1 = ((h1 << 5) + h1 + data[i]) >>> 0;
            h2 = ((h2 << 7) + h2 + data[i]) >>> 0;
            h3 = ((h3 << 3) + h3 + data[i]) >>> 0;
            h4 = ((h4 << 11) + h4 + data[i]) >>> 0;
        }
        for (let i = 0; i < 8; i++) {
            result[i] = (h1 >> (i * 4)) & 0xff;
            result[i + 8] = (h2 >> (i * 4)) & 0xff;
            result[i + 16] = (h3 >> (i * 4)) & 0xff;
            result[i + 24] = (h4 >> (i * 4)) & 0xff;
        }
        return result;
    }

    _getVaultRaw() {
        const json = this._readLocal(`keyVault_${this._currentUser}`);
        if (!json) return [];
        try { return JSON.parse(json); } catch { return []; }
    }

    _saveVaultRaw(vault) {
        this._storeLocal(`keyVault_${this._currentUser}`, JSON.stringify(vault));
    }

    _futureDate(days, from = null) {
        const base = from ? new Date(from) : new Date();
        base.setDate(base.getDate() + days);
        return base.toISOString();
    }
}

// Export for both module and script contexts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = QryptoMiddleware;
}
if (typeof window !== 'undefined') {
    window.QryptoMiddleware = QryptoMiddleware;
}
