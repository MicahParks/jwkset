function hide(j) {
  j.addClass('hidden');
}

function unhide(j) {
  j.removeClass('hidden');
}

$(function () {
  let mobileMenuButton = $('#mobile-menu-button');
  let mobileMenuIcon = $('#mobile-menu-icon');
  let mobileMenu = $('#mobile-menu');
  mobileMenuButton.on('click', function () {
    mobileMenuIcon.toggleClass('fa-bars fa-x');
    mobileMenu.toggleClass('hidden');
  });
});

// https://stackoverflow.com/a/6677069/14797322
function scroll(e) {
  $([document.documentElement, document.body]).animate({
    scrollTop: e.offset().top
  }, 500);
}

function postReCAPTCHA(action, complete, data, postURL, siteKey) {
  if (reCAPTCHASiteKey === '') {
    $.ajax(postURL, {
      accepts: 'application/json',
      contentType: 'application/json',
      data: JSON.stringify(data),
      dataType: 'json',
      method: 'POST',
      complete: complete,
    });
    return
  }
  grecaptcha.ready(function () {
    grecaptcha.execute(siteKey, {action: action}).then(function (token) {
      $.ajax(postURL, {
        accepts: 'application/json',
        contentType: 'application/json',
        data: JSON.stringify(data),
        dataType: 'json',
        headers: {
          'g-recaptcha-response': token,
        },
        method: 'POST',
        complete: complete,
      });
    });
  });
}