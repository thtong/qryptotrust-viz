
    // AES-256-GCM fallback — detect secure context
    window._hasSubtle = !!(typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.importKey);
    console.log('[AES] crypto.subtle available:', window._hasSubtle);
    