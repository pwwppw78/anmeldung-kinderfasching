document.addEventListener("DOMContentLoaded", function() {
    var bankButton = document.querySelector(".bank-button");
    var bankDetails = document.getElementById("bank-details");

    if (bankButton) {
        bankButton.addEventListener("click", function() {
            if (bankDetails.style.display === "none" || bankDetails.style.display === "") {
                bankDetails.style.display = "block";
            } else {
                bankDetails.style.display = "none";
            }
        });
    }

    var paypalButton = document.querySelector(".paypal-button");
    if (paypalButton) {
        paypalButton.addEventListener("click", function() {
            window.open("https://paypal.me/pascalweibler?country.x=DE&locale.x=de_DE", "_blank");
        });
    }
});
