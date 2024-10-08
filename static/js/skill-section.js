document.addEventListener('DOMContentLoaded', function () {

    const ExpertiseLevel = {
        Beginner: "Beginner",
        Intermediate: "Intermediate",
        Proficient: "Proficient",
        Expert: "Expert",
    };

    // let skillFormsContainer = document.getElementById('skill-forms-container');
    let addAnotherBtn = document.getElementById('add-another-btn');
    let nextBtn = document.getElementById('next-btn');

    nextBtn.addEventListener('click', submitForm);
    addAnotherBtn.addEventListener('click', () => insertSkillForm(skillInfo = {}));

    // Loading cached data if exists
    loadCached();
    setProgressBar(Page.skill);

    function submitForm(){
        cachedskillInfo()
        window.location.href = `/resume/section/summary?template_id=${TEMPLATE_ID}`;
    }


    function removeSkillForm(skillFormWrapper) {
        let isConfirmed = confirm("Are you sure you want to delete this skillcation entry?");

        if (!isConfirmed) {
            return
        }

        skillFormWrapper.classList.add('fade-out');
        setTimeout(() => {
            skillFormWrapper.remove();
            cachedskillInfo();
        }, 300);
    }

    function generateOptions(optionEnum, selectedLevel) {
        const options = Object.values(optionEnum).map(level => {
            return `<option value="${level}" ${selectedLevel === level ? 'selected' : ''}>${level}</option>`;
        });
        return options.join('');
    }


    function insertSkillForm(skillInfo = {}, showRemoveBtn = true) {
        if (Object.keys(skillInfo).length == 0) {
            skillInfo = {
                skill: "",
                expertiseLevel: ExpertiseLevel.Beginner
            }
        }

        let skillFormWrapper = document.createElement('div');
        skillFormWrapper.classList.add('skill-form-wrapper');

        skillFormWrapper.innerHTML = `
            <form class="skill-form">
                <div>
                    <label for="skill">Skill</label>
                    <input type="text" name="skill" value="${skillInfo.skill}" required>
                </div>
    
                <div>
                    <label for="expertiseLevel">Expertise Level</label>
                    <select name="expertiseLevel" required>
                        ${generateOptions(ExpertiseLevel, skillInfo.expertiseLevel)}
                    </select>
                </div>
    
                ${showRemoveBtn ? '<button type="button" class="remove-form-btn"><i class="fas fa-trash-alt"></i></button>' : ''}
            </form>
        `;

        let skillFormsContainer = document.getElementById('skill-forms-container');
        let removeBtn = skillFormWrapper.querySelector(".remove-form-btn");
        if (removeBtn) {
            removeBtn.addEventListener('click', () => removeSkillForm(skillFormWrapper));

            skillFormWrapper.addEventListener('mouseover', function () {
                removeBtn.classList.add('showed-remove-btn');
            });

            skillFormWrapper.addEventListener('mouseout', function () {
                removeBtn.classList.remove('showed-remove-btn');
            });
        }

        skillFormsContainer.appendChild(skillFormWrapper);
    }

    function cachedskillInfo() {
        let skillForms = document.querySelectorAll('.skill-form');
        let skillInfo = [];

        skillForms.forEach(form => {
            let skillData = {
                skill: form.querySelector('input[name="skill"]').value,
                expertiseLevel: form.querySelector('select[name="expertiseLevel"]').value,
            };
            skillInfo.push(skillData);
        });

        localStorage.setItem(CACHE_NAMES.SKILL, JSON.stringify(skillInfo));

   
    }


    function loadCached() {
        let cachedData = localStorage.getItem(CACHE_NAMES.SKILL);

        if (cachedData) {
            let skillData = JSON.parse(cachedData);

            let skillFormsContainer = document.getElementById('skill-forms-container');
            skillFormsContainer.innerHTML = '';
            let formCount = 0;

            skillData.forEach(skillInfo => {
                formCount++;
                if (formCount == 1) {
                    insertSkillForm(skillInfo, false);
                } else {
                    insertSkillForm(skillInfo);
                }
            });
        } else {
            insertSkillForm(skillInfo = {}, showRemoveBtn = false);
        }
    }


});