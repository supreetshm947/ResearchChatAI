$(document).ready(function () {
    // Listen for click on radioButton
    $('.radioButton').on('click', function () {
        // Get the fieldKey attribute
        var fieldKey = $(this).attr('fieldKey');
        // Get the fieldValue attribute
        var fieldValue = $(this).attr('fieldValue');
        // Get the target attribute
        var target = $(this).attr('radioAccordionTarget');

        // Make sure the above variables are not undefined
        if (typeof fieldKey === 'undefined' || typeof fieldValue === 'undefined' || typeof target === 'undefined') {
            return;
        }

        // Remove active class from all radioButtons on same level
        $(this).siblings().removeClass('active');
        // Add active class to clicked radioButton
        $(this).addClass('active');

        // Hide all siblings with .followUpContainer
        $(this).siblings('.followUpContainer').hide();
        // Add active class to target
        $(target).show();

        // log all variables separately with name
        console.log('fieldKey: ' + fieldKey);
        console.log('fieldValue: ' + fieldValue);
        console.log(target);

        // Save changes
        saveChanges(fieldKey, fieldValue);
    });
});