// jQuery code to listen to click on .mbToggle
$(document).on('click', '.mbToggle', function () {
    // Get the mbToggleTargets attribute value
    var mbToggleTargets = $(this).attr('mbToggleTargets');
    // Make sure that the mbToggleTargets is not empty
    if (mbToggleTargets == undefined) {
        return;
    }

    // Get the mbToggleCheckedAction attribute value
    var mbToggleCheckedAction = $(this).attr('mbToggleCheckedAction');
    // Set default action to hide
    if (mbToggleCheckedAction == undefined) {
        mbToggleCheckedAction = 'hide';
    }

    // Get the checked status of the checkbox
    var isChecked = $(this).is(':checked');

    // Loop over the targets
    $(mbToggleTargets.split(',')).each(function (index, target) {
        // If the mbToggleCheckedAction is hide
        if (mbToggleCheckedAction == 'hide') {
            // If the checkbox is checked
            if (isChecked) {
                // Hide the targets
                $(target).hide();
            } else {
                // Show the targets
                $(target).show();
            }
        }

        // If the mbToggleCheckedAction is show
        if (mbToggleCheckedAction == 'show') {
            // If the checkbox is checked
            if (isChecked) {
                // Show the targets
                $(target).show();
            } else {
                // Hide the targets
                $(target).hide();
            }
        }

        // If the mbToggleCheckedAction is disable
        if (mbToggleCheckedAction == 'disable') {
            // If the checkbox is checked
            if (isChecked) {
                // Check if the target is a tinymce editor (remove # and . from the target)
                if (tinymce.get(target.replace('#', '').replace('.', ''))) {
                    tinymce.get('participantInstructionsTextInput').mode.set('readonly');
                }
                else{
                    // Enable the targets
                    $(target).prop('disabled', true);
                }
            } else {
                // Check if the target is a tinymce editor
                if (tinymce.get(target.replace('#', '').replace('.', ''))) {
                    tinymce.get('participantInstructionsTextInput').mode.set('design');
                }
                else{
                    // Enable the targets
                    $(target).prop('disabled', false);
                }
            }
        }

        // If the mbToggleCheckedAction is enable
        if (mbToggleCheckedAction == 'enable') {
            // If the checkbox is checked
            if (isChecked) {
                // Check if the target is a tinymce editor (remove # and . from the target)
                if (tinymce.get(target.replace('#', '').replace('.', ''))) {
                    tinymce.get('participantInstructionsTextInput').mode.set('design');
                }
                else{
                    // Enable the targets
                    $(target).prop('disabled', false);
                }
            } else {
                // Check if the target is a tinymce editor
                if (tinymce.get(target.replace('#', '').replace('.', ''))) {
                    tinymce.get('participantInstructionsTextInput').mode.set('readonly');
                }
                else{
                    // Enable the targets
                    $(target).prop('disabled', true);
                }
            }
        }
    });
});