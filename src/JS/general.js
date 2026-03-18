$(document).ready(function () {
    // Listen for click on openModalButton for renameStudy to prefill the current study value
    $('button[data-target="renameStudyModal"]').on('click', function () {
        // Get the current study name
        var studyName = $('#studyName').text().trim();
        // Set the current study name as the value of the input field
        $('#newStudyNameInput').val(studyName);
    });

    // Listen for click on .saveNewNameButton
    $('.saveNewNameButton').on('click', function () {
        var newName = $('#newStudyNameInput').val();

        // Check if the new name is not empty
        if (newName.length <= 0) {
            alert("Please enter a name");
            return;
        }

        // Update the study name
        $('#studyName').text(newName);

        // Save the new name to the database
        saveChanges("studyName", newName);

        // Close the modal
        closeAllModals();
    });

    // Listen for click on .deleteStudyButton
    $('.deleteStudyButton').one('click', function () {
        closeAllModals();

        $.post(
            'Backend/Studies/study-delete.php',
            { csrf_token: csrfToken, studyID: studyID },
            function (data) {
                if (data.status !== 'good') {
                    alert(data.message || 'Delete failed');
                    return;
                }
                window.location.href = 'index.php';
            },
            'json'
        ).fail(function (xhr) {
            console.log(xhr);
            alert('An error occurred while deleting the study');
        });
    });

    // Listen for click on previewStudyButton
    $('#previewStudyButton').on('click', function () {
        // Get the passed variables in previewPassedVariablesList as an arry including values. only get the values of the passed variables that are not empty
        var passedVariables = [];
        $('#previewPassedVariablesList .columns').each(function () {
            var passedVariable = $(this).find('[name="parameterInput"]').val();
            var passedVariableValue = $(this).find('[name="parameterValueInput"]').val();
            if (passedVariable !== '' && passedVariableValue !== '') {
                passedVariables.push({ passedVariable: passedVariable, passedVariableValue: passedVariableValue });
            }
        });

        // Create preview URL
        var previewURL = `preview.php?studyCode=${studyCode}&preview=1`;

        // Add passed variables to the URL
        passedVariables.forEach((passedVariable) => {
            previewURL += `&${passedVariable.passedVariable}=${passedVariable.passedVariableValue}`;
        });

        // Open previewURL in new tab
        window.open(previewURL, '_blank').focus();
    });
});

////// MODAL CONTROL //////

// Get parameters passed in URL
function getURLParameter(name) {
    var parameter = decodeURIComponent((new RegExp('[?|&]' + name + '=' + '([^&;]+?)(&|#|;|$)').exec(location.search) || [null, ''])[1].replace(/\+/g, '%20')) || null;

    if (isEmptyOrSpaces(parameter)) {
        parameter = "";
    }

    return parameter
}

// Check whether a string is empty or contains only spaces
function isEmptyOrSpaces(str) {
    return str === null || str.match(/^ *$/) !== null;
}

// Modal controls
// Functions to open and close a modal
function openModal($el) {
    $el.classList.add('is-active');
}

function closeModal($el) {
    $el.classList.remove('is-active');
}

function closeAllModals() {
    (document.querySelectorAll('.modal') || []).forEach(($modal) => {
        closeModal($modal);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Add a click event on buttons to open a specific modal
    (document.querySelectorAll('.js-modal-trigger') || []).forEach(($trigger) => {
        const modal = $trigger.dataset.target;
        const $target = document.getElementById(modal);

        $trigger.addEventListener('click', () => {
            openModal($target);
        });
    });

    // Add a click event on various child elements to close the parent modal
    (document.querySelectorAll('.modal-background, .modal-close, .modal-card-head .delete, .cancel') || []).forEach(($close) => {
        const $target = $close.closest('.modal');

        $close.addEventListener('click', () => {
            closeModal($target);
        });
    });

    // Add a keyboard event to close all modals
    document.addEventListener('keydown', (event) => {
        if (event.key === "Escape") {
            closeAllModals();
        }
    });
});

// Handle navbar burger click
$(document).ready(function () {

    // Check for click events on the navbar burger icon
    $(".navbar-burger").click(function () {

        // Toggle the "is-active" class on both the "navbar-burger" and the "navbar-menu"
        $(".navbar-burger").toggleClass("is-active");
        $(".navbar-menu").toggleClass("is-active");

    });
});