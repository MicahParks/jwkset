$(function () {
  let jwkInspectButton = $('#jwk-inspect-button');
  let jwkInput = $('#jwk-input');
  let inspectResults = $('#inspect-results');
  let jwkResult = $('#jwk-result');
  let jwkResultText = $('#jwk-result-text');
  let pkcs8Result = $('#pkcs8-result');
  let pkcs8ResultText = $('#pkcs8-result-text');
  let pkixResult = $('#pkix-result');
  let pkixResultText = $('#pkix-result-text');
  let resultButton = $('#result-button');
  let resultText = $('#result-text');

  jwkInput.on('input', function () {
    let jwk = jwkInput.val();
    if (jwk) {
      jwkInspectButton.prop('disabled', false);
      jwkInspectButton.removeClass('cursor-not-allowed').addClass('cursor-pointer');
      jwkInspectButton.removeClass('bg-indigo-400').addClass('bg-indigo-600 hover:bg-indigo-500');
    } else {
      jwkInspectButton.prop('disabled', true);
      jwkInspectButton.removeClass('cursor-pointer').addClass('cursor-not-allowed');
      jwkInspectButton.removeClass('bg-indigo-600 hover:bg-indigo-500').addClass('bg-indigo-400');
    }
  });

  function complete(jqXHR, status) {
    switch (jqXHR.status) {
      case 200:
        resultText.text('The JWK is valid. The parsing results are below.');
        resultButton.removeClass('bg-red-600').addClass('bg-green-600');
        resultButton.contents().filter(function () {
          return this.nodeType === 3;
        }).first().replaceWith('Valid');
        resultButton.find('i').removeClass('fa-circle-xmark').addClass('fa-circle-check');
        unhide(inspectResults);
        unhide(jwkResult);
        jwkResultText.text(jqXHR.responseJSON.data.jwk);
        let pkcs8 = jqXHR.responseJSON.data.pkcs8;
        if (pkcs8) {
          pkcs8ResultText.text(pkcs8);
          unhide(pkcs8Result);
        } else {
          hide(pkcs8Result);
        }
        let pkix = jqXHR.responseJSON.data.pkix;
        if (pkix) {
          pkixResultText.text(pkix);
          unhide(pkixResult);
        } else {
          hide(pkixResult);
        }
        scroll(inspectResults);
        break;
      default:
        let message = jqXHR.responseJSON?.data?.message;
        resultText.text(`The JWK is invalid. ${message}`);
        resultButton.removeClass('bg-green-600').addClass('bg-red-600');
        resultButton.contents().filter(function () {
          return this.nodeType === 3;
        }).first().replaceWith('Invalid');
        resultButton.find('i').removeClass('fa-circle-check').addClass('fa-circle-xmark');
        unhide(inspectResults);
        hide(jwkResult);
        hide(pkcs8Result);
        hide(pkixResult);
    }
    scroll(inspectResults);
  }

  jwkInspectButton.on('click', function () {
    let data = {
      jwk: jwkInput.val(),
    };
    postReCAPTCHA('inspect', complete, data, pathAPIInspect, reCAPTCHASiteKey);
  });
});
