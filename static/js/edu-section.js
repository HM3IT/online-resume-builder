document.addEventListener('DOMContentLoaded', function () {

    let typingTimer;
    let eduFormsContainer = document.getElementById('edu-forms-container');
    let addAnotherBtn = document.getElementById('add-another-btn');
    let submitBtn = document.getElementById('next-btn');

    submitBtn.addEventListener('click', submitForm);
    addAnotherBtn.addEventListener('click', () => insertEducationForm(eduInfo = {}));

    // Loading cached data if exists
    loadCached();
    loadResumePreview(Page.education)
    setProgressBar(Page.education)

    function setMaxEndDate(form) {
        let today = new Date();
        let year = today.getFullYear();
        let month = String(today.getMonth() + 1).padStart(2, '0');
        let day = String(today.getDate()).padStart(2, '0');
        let todayDate = `${year}-${month}-${day}`;
        form.querySelector('input[name="end-date"]').setAttribute("max", todayDate);
    }

    // setting the end-date of the first education form
    setMaxEndDate(document.querySelector('.edu-form'));

    function removeEducationForm(eduFormWrapper) {
        let isConfirmed = confirm("Are you sure you want to delete this education entry?");

        if (!isConfirmed) {
            return
        }

        eduFormWrapper.classList.add('fade-out');
        setTimeout(() => {
            eduFormWrapper.remove();
            handleEduInfo()
        }, 300);
    }



    function insertEducationForm(eduInfo = {}, showRemoveBtn = true) {
        if (Object.keys(eduInfo).length == 0) {
            eduInfo = {
                degree: '',
                school: '',
                location: '',
                start_date: '0-0-0',
                end_date: '0-0-0',
                is_studying: false
            }
                ;
        }


        let eduFormWrapper = document.createElement('div');
        eduFormWrapper.classList.add('edu-form-wrapper');

        eduFormWrapper.innerHTML = `
                <form class="edu-form">
                    <div>
                        <label for="degree">Degree</label>
                        <input type="text" name="degree" value="${eduInfo.degree}" required>
                    </div>
                    <div>
                        <label for="school">Name of School/University</label>
                        <input type="text" name="school" value="${eduInfo.school}" required>
                    </div>
                    <div class="location-div">
                        <label for="location">Location</label>
                        <input type="text" name="location" value="${eduInfo.location}" required>
                    </div>
                    <div class="date-div">
                        <div>
                            <label for="start-date">Start Date</label>
                            <input type="date" id="start-date" name="start-date" value="${eduInfo.start_date}" required>
                        </div>
                        <div>
                            <label for="end-date">End Date</label>
                            <input type="date" id="end-date" name="end-date" value="${eduInfo.end_date}" ${eduInfo.is_studying ? 'disabled' : ''}>
                        </div>
                        <input type="checkbox" name="is-studying" id="is-studying" ${eduInfo.is_studying ? 'checked' : ''}>
                        <label for="is-studying">I haven't graduated yet</label>
                    </div>
                    ${showRemoveBtn ? '<button type="button" class="remove-form-btn">Remove</button>' : ''}
                    
                </form>
                `;

        eduFormsContainer.appendChild(eduFormWrapper);

        setMaxEndDate(eduFormWrapper);

        let removeBtn = eduFormWrapper.querySelector(".remove-form-btn");
        let isStudyingCheckbox = eduFormWrapper.querySelector("#is-studying")
        let endDateInput = eduFormWrapper.querySelector("#end-date")

        isStudyingCheckbox.addEventListener('change', () => {
            if (isStudyingCheckbox.checked) {
                endDateInput.value = "0-0/-0"
                endDateInput.disabled = true;
            } else {
                endDateInput.disabled = false;
            }
        })
        if (removeBtn) {
            removeBtn.addEventListener('click', () => removeEducationForm(eduFormWrapper));

            eduFormWrapper.addEventListener('mouseover', function () {
                removeBtn.classList.add('showed-remove-btn');
            });

            eduFormWrapper.addEventListener('mouseout', function () {
                removeBtn.classList.remove('showed-remove-btn');
            });

        }
    }
    function handleEduInfo() {
        let currentData = getEduFormData()
        checkForUpdate(CACHE_NAMES.EDU, currentData);
    }

    function getEduFormData() {
        let currentData = [];
        let eduForms = document.querySelectorAll('.edu-form');

        eduForms.forEach(form => {
            let eduData = {
                degree: form.querySelector('input[name="degree"]').value,
                school: form.querySelector('input[name="school"]').value,
                location: form.querySelector('input[name="location"]').value,
                start_date: form.querySelector('input[name="start-date"]').value,
                end_date: form.querySelector('input[name="end-date"]').value,
                is_studying: form.querySelector('input[name="is-studying"]').checked
            };



            currentData.push(eduData);
        });
        return currentData
    }


    // setInterval(handleEduInfo, pollingInterval);
    document.addEventListener('input', () => {
        clearTimeout(typingTimer);
        typingTimer = setTimeout(handleEduInfo, INPUT_TYPING_DELAY);
    });



    function submitForm() {
        let currentData = getEduFormData();

        //data validation for the final form submit
        let isValid = true
        currentData.forEach(eduData => {

            if (eduData.degree.length == 0 || eduData.school.length == 0 || eduData.location.length == 0) {
                showInformBox('Please fill all the education fields!', InformType.WARNING);
                isValid = false;
                return;
            }

            if (eduData.start_date.length == 0 || !hasDay(eduData.start_date)) {
                showInformBox('Please include the day in the start date (format:  09/17/2024).', InformType.FAIL);
                isValid = false;
                return;
            }

            if (!hasDay(eduData.end_date)) {
                if (!eduData.is_studying) {
                    showInformBox('Please include the day in the end date (format: 09/17/2024) or check "Still working".', InformType.FAIL);
                    isValid = false;
                    return;
                }
            } else {
                const startDate = new Date(eduData.start_date);
                const endDate = new Date(eduData.end_date);

                if (startDate > endDate) {
                    showInformBox('Start date cannot be after the end date.', InformType.FAIL);
                    isValid = false;
                    return;
                }
            }
        })
        if (isValid) {
            checkForUpdate(CACHE_NAMES.EDU, currentData);
            window.location.href = `/resume/section/work_experience?template_id=${TEMPLATE_ID}`;
        }

    }


    function loadCached() {

        let cachedData = localStorage.getItem(CACHE_NAMES.EDU);

        if (cachedData) {
            let educationData = JSON.parse(cachedData);

            let eduFormsContainer = document.getElementById('edu-forms-container');
            eduFormsContainer.innerHTML = '';
            formCount = 0
            educationData.forEach(eduInfo => {
                // Hidden the remove button in the first education entry form 
                formCount++
                if (formCount == 1) {
                    insertEducationForm(eduInfo, false)
                } else {

                    insertEducationForm(eduInfo)
                }
            });
        } else {
            insertEducationForm(eduInfo = {}, showRemoveBtn = false)
        }
    }

});