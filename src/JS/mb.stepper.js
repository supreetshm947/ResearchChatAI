$(document).ready(function () {
    // Implement logic for stepper to hide respective containers and update classes
    $('.stepper').on('click', function () {
        // Get the target container
        var targetContainer = $(this).attr('data-target');

        // Set step group --> This allows to potentially have multiple steppers on the same page
        var stepGroup = "step";

        // Hide all containers
        $('.stepContainer').hide();

        // Show the target container
        $('#' + targetContainer).show();

        // Add inactive class to all buttons and remove other ones
        $('.c-stepper__item').addClass('inactive');
        $('.c-stepper__item').addClass('active');
        $('.c-stepper__item').removeClass('current');

        // Add the current class to the clicked button
        $(this).closest(".c-stepper__item").addClass('current');
        // Remove inactive class from the clicked button
        $(this).closest(".c-stepper__item").removeClass('inactive');

        // Add the active class to the clicked button
        $(this).closest(".c-stepper__item").addClass('active');

        // Add the active class to the buttons before the clicked button
        $(this).closest(".c-stepper__item").prevAll().removeClass('inactive').addClass("active");

        // Save current step to URL prameter while preserving other parameters
        var urlParams = new URLSearchParams(window.location.search);
        urlParams.set(stepGroup, $(this).attr('id'));
        window.history.replaceState({}, '', `${location.pathname}?${urlParams}`);
    });

    // Listen for click on .goToStepButton and click on the corresponding step
    $('.goToStepButton').on('click', function () {
        var targetStep = $(this).data('target');

        goToStep(targetStep);
    });

    // Load step from URL if specified and simulate click on the corresponding step
    var urlParams = new URLSearchParams(window.location.search);
    var step = urlParams.get('step');
    console.log(step);
    if (step) {
        // Get step button
        var stepButton = $('#' + step);
        console.log(stepButton);
        if (stepButton) {
            // Click on the step button
            stepButton.click();
            console.log('clicked');
        }
    }
});

// Function to go to a specific step
function goToStep(targetStep){
    // Get nth c-stepper__item
    var stepperItem = $('.c-stepper__item').eq(targetStep - 1);
    // Click on the stepperItem
    stepperItem.find('.stepper').click();
    // Scroll to top with animation
    $('html, body').animate({
        scrollTop: 0
    }, 500);
}