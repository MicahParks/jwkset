const keyTypeRSA = 'RSA';
const keyTypeECDSA = 'ECDSA';
const keyTypeEd25519 = 'Ed25519';
const keyTypeX25519 = 'X25519';
const keyTypeSymmetric = 'Symmetric';

$(function () {
  let newGenButton = $('#new-gen-button');
  let newKeyType = $('input[name="new-key-type"]');
  let newKeyID = $('#new-key-id');
  let newKeyAlg = $('#new-key-alg');
  let newKeyAlgOptional = $('#new-key-alg-optional');
  let newUse = $('#new-key-use');
  let newKeyOpSign = $('#new-key-op-sign');
  let newKeyOpVerify = $('#new-key-op-verify');
  let newKeyOpEncrypt = $('#new-key-op-encrypt');
  let newKeyOpDecrypt = $('#new-key-op-decrypt');
  let newKeyOpWrapKey = $('#new-key-op-wrap-key');
  let newKeyOpUnwrapKey = $('#new-key-op-unwrap-key');
  let newKeyOpDeriveKey = $('#new-key-op-derive-key');
  let newKeyOpDeriveBits = $('#new-key-op-derive-bits');
  let newRSABitsChoice = $('input[name="new-rsa-bits"]');
  let newECDSACurveChoice = $('input[name="new-ecdsa-curve"]');
  let newRSABits = $('#new-rsa-bits');
  let newECDSACurve = $('#new-ecdsa-curve');
  let newGenCopyJWK = $('#new-gen-copy-jwk');
  let newGenCopyPKCS8 = $('#new-gen-copy-pkcs8');
  let newGenCopyPKIX = $('#new-gen-copy-pkix');
  let newGenResults = $('#new-gen-results');
  let newGenJWKResult = $('#new-gen-jwk-result');
  let newGenPKCS8Result = $('#new-gen-pkcs8-result');
  let newGenPKIXResult = $('#new-gen-pkix-result');
  let newGenPKCS8 = $('#new-gen-pkcs8');
  let newGenPKIX = $('#new-gen-pkix');
  let newResultButton = $('#new-result-button');
  let newResultText = $('#new-result-text');
  let newResultsList = $('#new-results-list');

  let pemGenButton = $('#pem-gen-button');
  let pemInput = $('#pem-input');
  let pemKeyID = $('#pem-key-id');
  let pemKeyAlg = $('#pem-key-alg');
  let pemKeyUse = $('#pem-key-use');
  let pemKeyOpSign = $('#pem-key-op-sign');
  let pemKeyOpVerify = $('#pem-key-op-verify');
  let pemKeyOpEncrypt = $('#pem-key-op-encrypt');
  let pemKeyOpDecrypt = $('#pem-key-op-decrypt');
  let pemKeyOpWrapKey = $('#pem-key-op-wrap-key');
  let pemKeyOpUnwrapKey = $('#pem-key-op-unwrap-key');
  let pemKeyOpDeriveKey = $('#pem-key-op-derive-key');
  let pemKeyOpDeriveBits = $('#pem-key-op-derive-bits');
  let pemGenCopyJWK = $('#pem-gen-copy-jwk');
  let pemGenResults = $('#pem-gen-results');
  let pemGenJWKResult = $('#pem-gen-jwk-result');
  let pemResultButton = $('#pem-result-button');
  let pemResultText = $('#pem-result-text');
  let pemResultsList = $('#pem-results-list');
  pemKeyID.val(crypto.randomUUID());

  pemGenCopyJWK.on('click', function () {
    navigator.clipboard.writeText(pemGenJWKResult.text());
  });
  newGenCopyJWK.on('click', function () {
    navigator.clipboard.writeText(newGenJWKResult.text());
  });
  newGenCopyPKCS8.on('click', function () {
    navigator.clipboard.writeText(newGenPKCS8Result.text());
  });
  newGenCopyPKIX.on('click', function () {
    navigator.clipboard.writeText(newGenPKIXResult.text());
  });

  function pemGenCompete(jqXHR, status) {
    switch (jqXHR.status) {
      case 200:
        pemResultText.text('The PEM is valid. The JWK results are below.');
        pemResultButton.removeClass('bg-red-600').addClass('bg-green-600');
        pemResultButton.contents().filter(function () {
          return this.nodeType === 3;
        }).first().replaceWith('Valid');
        pemResultButton.find('i').removeClass('fa-circle-xmark').addClass('fa-circle-check');
        unhide(pemGenResults);
        unhide(pemResultsList);
        pemGenJWKResult.text(jqXHR.responseJSON.data.jwk);
        break;
      default:
        let message = jqXHR.responseJSON?.data?.message;
        pemResultText.text(`The PEM generation failed. ${message}`);
        pemResultButton.removeClass('bg-green-600').addClass('bg-red-600');
        pemResultButton.contents().filter(function () {
          return this.nodeType === 3;
        }).first().replaceWith('Invalid');
        unhide(pemGenResults);
        hide(pemResultsList);
        pemResultButton.find('i').removeClass('fa-circle-check').addClass('fa-circle-xmark');
    }
    scroll(pemGenResults);
  }

  pemGenButton.on('click', function () {
    let keyOps = [];
    if (pemKeyOpSign.is(':checked')) {
      keyOps.push('sign');
    }
    if (pemKeyOpVerify.is(':checked')) {
      keyOps.push('verify');
    }
    if (pemKeyOpEncrypt.is(':checked')) {
      keyOps.push('encrypt');
    }
    if (pemKeyOpDecrypt.is(':checked')) {
      keyOps.push('decrypt');
    }
    if (pemKeyOpWrapKey.is(':checked')) {
      keyOps.push('wrapKey');
    }
    if (pemKeyOpUnwrapKey.is(':checked')) {
      keyOps.push('unwrapKey');
    }
    if (pemKeyOpDeriveKey.is(':checked')) {
      keyOps.push('deriveKey');
    }
    if (pemKeyOpDeriveBits.is(':checked')) {
      keyOps.push('deriveBits');
    }
    let data = {
      alg: pemKeyAlg.val(),
      keyops: keyOps,
      kid: pemKeyID.val(),
      pem: pemInput.val(),
      use: pemKeyUse.val(),
    };
    postReCAPTCHA('pemGen', pemGenCompete, data, pathAPIPemGen, reCAPTCHASiteKey);
  });

  pemInput.on('input', function () {
    let val = pemInput.val();
    if (val === '') {
      pemGenButton.prop('disabled', true);
      pemGenButton.removeClass('cursor-pointer').addClass('cursor-not-allowed');
      pemGenButton.removeClass('bg-indigo-600 hover:bg-indigo-500').addClass('bg-indigo-400');
    } else {
      pemGenButton.prop('disabled', false);
      pemGenButton.removeClass('cursor-not-allowed').addClass('cursor-pointer');
      pemGenButton.removeClass('bg-indigo-400').addClass('bg-indigo-600 hover:bg-indigo-500');
    }
  });

  function newGenCompete(jqXHR, status) {
    switch (jqXHR.status) {
      case 200:
        newResultText.text('The results from the new key generation.');
        newResultButton.removeClass('bg-red-600').addClass('bg-green-600');
        newResultButton.contents().filter(function () {
          return this.nodeType === 3;
        }).first().replaceWith('Valid');
        newResultButton.find('i').removeClass('fa-circle-xmark').addClass('fa-circle-check');
        unhide(newGenResults);
        unhide(newResultsList);
        newGenJWKResult.text(jqXHR.responseJSON.data.jwk);
        if (jqXHR.responseJSON.data.pkcs8) {
          newGenPKCS8Result.text(jqXHR.responseJSON.data.pkcs8);
          unhide(newGenPKCS8);
        } else {
          hide(newGenPKCS8);
        }
        if (jqXHR.responseJSON.data.pkix) {
          newGenPKIXResult.text(jqXHR.responseJSON.data.pkix);
          unhide(newGenPKIX);
        } else {
          hide(newGenPKIX);
        }
        break;
      default:
        let message = jqXHR.responseJSON?.data?.message;
        newResultText.text(`Key generation failed. ${message}`);
        newResultButton.removeClass('bg-green-600').addClass('bg-red-600');
        newResultButton.contents().filter(function () {
          return this.nodeType === 3;
        }).first().replaceWith('Invalid');
        unhide(newGenResults);
        hide(newResultsList);
        newResultButton.find('i').removeClass('fa-circle-check').addClass('fa-circle-xmark');
    }
    scroll(newGenResults);
  }

  newGenButton.on('click', function () {
    let keyOps = [];
    if (newKeyOpSign.is(':checked')) {
      keyOps.push('sign');
    }
    if (newKeyOpVerify.is(':checked')) {
      keyOps.push('verify');
    }
    if (newKeyOpEncrypt.is(':checked')) {
      keyOps.push('encrypt');
    }
    if (newKeyOpDecrypt.is(':checked')) {
      keyOps.push('decrypt');
    }
    if (newKeyOpWrapKey.is(':checked')) {
      keyOps.push('wrapKey');
    }
    if (newKeyOpUnwrapKey.is(':checked')) {
      keyOps.push('unwrapKey');
    }
    if (newKeyOpDeriveKey.is(':checked')) {
      keyOps.push('deriveKey');
    }
    if (newKeyOpDeriveBits.is(':checked')) {
      keyOps.push('deriveBits');
    }
    let data = {
      alg: newKeyAlg.val(),
      keyops: keyOps,
      keyType: newKeyType.filter(':checked').val(),
      kid: newKeyID.val(),
      use: newUse.val(),
      rsaBits: parseInt(newRSABitsChoice.filter(':checked').val()),
      ecCurve: newECDSACurveChoice.filter(':checked').val(),
    };
    postReCAPTCHA('newGen', newGenCompete, data, pathAPINewGen, reCAPTCHASiteKey);
  });

  let rsaAlgs = [
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512',
    'RSA1_5',
    'RSA-OAEP',
    'RSA-OAEP-256',
    'RSA-OAEP-384',
    'RSA-OAEP-512',
  ]; // RS1 Prohibited.
  let ecdsaAlgs = [
    'ES256',
    'ES384',
    'ES512',
    'ES256K',
  ];
  let ed25519Algs = [
    'EdDSA',
  ];
  let x25519Algs = [
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
  ];
  let symmetricAlgs = [
    'HS256',
    'HS384',
    'HS512',
    'dir',
    'A128KW',
    'A192KW',
    'A256KW',
    'A128GCMKW',
    'A192GCMKW',
    'A256GCMKW',
    'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW',
    'A128CBC-HS256',
    'A192CBC-HS384',
    'A256CBC-HS512',
    'A128GCM',
    'A192GCM',
    'A256GCM',
  ];

  const emptySelection = '<option value="" selected></option>';
  pemKeyAlg.append(emptySelection);
  let pemAlgs = rsaAlgs.concat(ecdsaAlgs, ed25519Algs, x25519Algs);
  for (let i = 0; i < pemAlgs.length; i++) {
    let alg = pemAlgs[i];
    pemKeyAlg.append(`<option value="${alg}">${alg}</option>`);
  }

  function keyPanelChange(keyType) {
    newKeyID.val(crypto.randomUUID());
    let algs;
    switch (keyType) {
      case keyTypeRSA:
        hide(newECDSACurve);
        unhide(newRSABits);
        unhide(newKeyAlgOptional);
        algs = rsaAlgs;
        break;
      case keyTypeECDSA:
        unhide(newECDSACurve);
        hide(newRSABits);
        unhide(newKeyAlgOptional);
        algs = ecdsaAlgs;
        break;
      case keyTypeEd25519:
        hide(newECDSACurve);
        hide(newRSABits);
        hide(newKeyAlgOptional);
        algs = ed25519Algs;
        break;
      case keyTypeX25519:
        hide(newECDSACurve);
        hide(newRSABits);
        unhide(newKeyAlgOptional);
        algs = x25519Algs;
        break;
      case keyTypeSymmetric:
        hide(newECDSACurve);
        hide(newRSABits);
        unhide(newKeyAlgOptional);
        algs = symmetricAlgs;
        break;
      default:
        algs = [];
        console.log('Unknown key type: ' + keyType);
        break;
    }
    newKeyAlg.empty();
    if (keyType === keyTypeEd25519) {
      newKeyAlg.prop('disabled', true);
      newKeyAlg.append('<option value="EdDSA" selected>EdDSA</option>');
    } else {
      newKeyAlg.prop('disabled', false);
      newKeyAlg.append(emptySelection);
      for (let i = 0; i < algs.length; i++) {
        let alg = algs[i];
        newKeyAlg.append(`<option value="${alg}">${alg}</option>`);
      }
    }
    let selectionSignature = '<option value="sig">Signature</option>';
    let selectionEncryption = '<option value="enc">Encryption</option>';
    switch (keyType) {
      case keyTypeECDSA:
        newUse.empty();
        newUse.append(emptySelection);
        newUse.append(selectionSignature);
        break;
      case keyTypeEd25519:
        newUse.empty();
        newUse.append(emptySelection);
        newUse.append(selectionSignature);
        break;
      case keyTypeX25519:
        newUse.empty();
        newUse.append(emptySelection);
        newUse.append(selectionEncryption);
        break;
      default:
        newUse.empty();
        newUse.append(emptySelection);
        newUse.append(selectionSignature);
        newUse.append(selectionEncryption);
        break;
    }
  }

  keyPanelChange(keyTypeRSA);

  newKeyType.on('change', function () {
    let keyType = newKeyType.filter(':checked').val();
    keyPanelChange(keyType);
  });

  function radioChange(r) {
    r.on('change', function () {
      // Remove the active class from all options
      let parent = r.parent();
      const selected = 'bg-indigo-600 text-white hover:bg-indigo-500';
      const unselected = 'ring-1 ring-inset ring-gray-300 bg-white text-gray-900 hover:bg-gray-50';
      parent.removeClass(selected);
      parent.addClass(unselected);

      // Add the active class to the selected option
      let t = $(this).parent();
      t.removeClass(unselected);
      t.addClass(selected);
    });
  }

  radioChange(newRSABitsChoice);
  radioChange(newECDSACurveChoice);
});
