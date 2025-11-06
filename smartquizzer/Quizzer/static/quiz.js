// --- static/quiz.js ---

document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const quizSetup = document.getElementById('quiz-setup');
    const setupForm = document.getElementById('setup-form');
    const quizLoading = document.getElementById('quiz-loading');
    const quizContainer = document.getElementById('quiz-container');
    const quizResults = document.getElementById('quiz-results');

    // Quiz Container Elements
    const quizHeader = document.getElementById('quiz-header');
    const questionProgress = document.getElementById('question-progress');
    const currentScore = document.getElementById('current-score');
    const questionTimer = document.getElementById('question-timer');
    const questionText = document.getElementById('question-text');
    const answerOptions = document.getElementById('answer-options');
    const quizFooter = document.getElementById('quiz-footer');
    const submitAnswerBtn = document.getElementById('submit-answer');
    const nextQuestionBtn = document.getElementById('next-question');
    const questionTypeDisplay = document.getElementById('question-type-display'); // Added
    const mcqMultipleHint = document.getElementById('mcq-multiple-hint'); // <-- Ensure this is defined

    // Feedback Container Elements
    const feedbackContainer = document.getElementById('feedback-container');
    const feedbackIcon = document.getElementById('feedback-icon');
    const feedbackText = document.getElementById('feedback-text');
    const feedbackExplanation = document.getElementById('feedback-explanation');
    const feedbackHint = document.getElementById('feedback-hint');
    const feedbackHeader = document.getElementById('feedback-header');

    // Question Feedback Form
    const questionFeedbackForm = document.getElementById('question-feedback-form');
    const feedbackComment = document.getElementById('feedback-comment');
    const feedbackFlag = document.getElementById('feedback-flag');
    const feedbackAlert = document.getElementById('feedback-alert');

    // Results Screen Elements
    const finalScore = document.getElementById('final-score');
    const aiFeedbackContainer = document.getElementById('ai-feedback-container');
    const resultsReviewArea = document.getElementById('results-review-area');
    const retryQuizBtn = document.getElementById('retry-quiz');
    const newQuizBtn = document.getElementById('new-quiz');

    // Flash Notification Element
    const flashNotification = document.getElementById('flash-notification'); // Added

    // --- Quiz State ---
    let quizData = [];
    let currentQuestionIndex = 0;
    let score = 0;
    let performanceHistory = []; // List of booleans (correct/incorrect)
    let currentDifficulty = 'medium'; // Default, will be updated
    let answeredQuestions = []; // Stores {question, userAnswer, evaluation, feedback, timeSpent}
    let quizStartTime = null;
    let questionStartTime = null;
    let questionTimerInterval = null;
    let flashTimeout = null; // For flash message timer
    let totalQuizTime = 0; // Total time spent on quiz
    let questionTimes = []; // Array to store time spent on each question

    // --- Initial Setup ---
    if (quizSetup) {
        quizSetup.style.display = 'block'; // Show setup form initially
        setupForm?.addEventListener('submit', startQuiz); // Add null check
    } else {
        console.error("Quiz setup form not found!");
    }
    // Add null checks for buttons before adding listeners
    submitAnswerBtn?.addEventListener('click', handleSubmitAnswer);
    nextQuestionBtn?.addEventListener('click', loadNextQuestion);
    questionFeedbackForm?.addEventListener('submit', submitQuestionFeedback);
    retryQuizBtn?.addEventListener('click', () => window.location.reload());
    newQuizBtn?.addEventListener('click', () => window.location.href = '/');


    // --- 1. Start Quiz ---
    async function startQuiz(e) {
        e.preventDefault();
        if (!quizSetup || !quizLoading) return; // Safety check

        quizSetup.style.display = 'none';
        quizLoading.style.display = 'block';

        const topicInput = document.getElementById('topic');
        const numQuestionsInput = document.getElementById('num_questions');
        const difficultySelect = document.getElementById('difficulty');
        const materialIdInput = document.getElementById('material_id');

        // Get values safely
        const topic = topicInput?.value || 'General Knowledge';
        const num_questions = numQuestionsInput?.value || '10';
        const difficulty = difficultySelect?.value || 'medium';
        const material_id = materialIdInput?.value || '';

        currentDifficulty = difficulty; // Set initial difficulty from user choice

        try {
            const response = await fetch('/api/generate-quiz', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    topic: topic,
                    num_questions: parseInt(num_questions, 10),
                    difficulty: difficulty,
                    material_id: material_id ? parseInt(material_id, 10) : null
                })
            });

            quizLoading.style.display = 'none'; // Hide loading regardless of success/failure after fetch

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (!data.success || !Array.isArray(data.quiz) || data.quiz.length === 0) {
                 throw new Error(data.message || 'Received invalid quiz data from server.');
            }

            quizData = data.quiz;

            // Reset state
            currentQuestionIndex = 0;
            score = 0;
            performanceHistory = [];
            answeredQuestions = [];
            quizStartTime = new Date();

            if (quizContainer) quizContainer.style.display = 'block';
            loadQuestion(currentQuestionIndex);

        } catch (error) {
            console.error('Error starting quiz:', error);
            if (quizSetup) quizSetup.style.display = 'block'; // Show setup again on error
            // Show error to user
            alert(`Error generating quiz: ${error.message}\nPlease try again.`);
        }
    }

    // --- 2. Load Question ---
    function loadQuestion(index) {
        if (!quizData || index >= quizData.length) {
            showResults(); return;
        }

        // Reset UI
        if(feedbackContainer) feedbackContainer.style.display = 'none';
        if(feedbackContainer) feedbackContainer.className = 'card';
        if(questionFeedbackForm) questionFeedbackForm.reset();
        if(feedbackAlert) feedbackAlert.style.display = 'none';
        if(submitAnswerBtn) submitAnswerBtn.style.display = 'inline-block';
        if(nextQuestionBtn) nextQuestionBtn.style.display = 'none';
        if(submitAnswerBtn) submitAnswerBtn.disabled = false;
        if(mcqMultipleHint) mcqMultipleHint.style.display = 'none'; // <-- Hide hint initially

        const question = quizData[index];
        if (!question || !questionText || !questionProgress || !currentScore || !questionTypeDisplay) {
             console.error("Missing critical elements for loadQuestion."); return;
        }

        questionText.textContent = question.question || '[Missing Question]';
        questionProgress.textContent = `Question ${index + 1} of ${quizData.length}`;
        currentScore.textContent = `Score: ${score}`;

        // Display Question Type
        let displayType = 'Unknown';
        if (question.question_type) {
             displayType = question.question_type
                .replace('mcq_single', 'MCQ (Single)')
                .replace('mcq_multiple', 'MCQ (Multiple)')
                .replace('true_false', 'True/False')
                .replace('short_answer', 'Short Answer')
                .replace('fill_in_the_blank', 'Fill Blank');
        }
        questionTypeDisplay.textContent = displayType;

        // *** UPDATED HINT LOGIC ***
        // Show hint only if type is mcq_multiple AND there's actually more than one correct answer
        if (question.question_type === 'mcq_multiple' &&
            Array.isArray(question.correct_answer) &&
            question.correct_answer.length > 1 && // Check length
            mcqMultipleHint) { // Check variable exists
                mcqMultipleHint.style.display = 'block'; // <-- Show hint
        }
        // *** END UPDATED HINT LOGIC ***

        renderAnswerOptions(question);

        questionStartTime = new Date();
        startQuestionTimer();
    }

    // --- 3. Render Answer Options ---
    function renderAnswerOptions(question) {
        if (!answerOptions) return;
        answerOptions.innerHTML = ''; // Clear previous options
        const type = question.question_type;

        try { // Add try block for safety
            if (type === 'mcq_single' || type === 'true_false') {
                const options = (type === 'true_false') ? ['True', 'False'] : (question.options || []);
                if (options.length === 0 && type !== 'true_false') throw new Error("MCQ options missing");

                options.forEach((option, index) => {
                    const value = (type === 'true_false') ? (index === 0 ? 'true' : 'false') : index;
                    const optionEl = document.createElement('div');
                    optionEl.className = 'answer-option';
                    optionEl.innerHTML = `
                        <label>
                            <input type="radio" name="answer" value="${value}">
                            <span>${option || `Option ${index + 1}`}</span>
                        </label>
                    `;
                    answerOptions.appendChild(optionEl);
                });
            } else if (type === 'mcq_multiple') {
                const options = question.options || [];
                if (options.length < 2) throw new Error("MCQ Multiple needs at least 2 options");

                options.forEach((option, index) => {
                    const optionEl = document.createElement('div');
                    optionEl.className = 'answer-option';
                    optionEl.innerHTML = `
                        <label>
                            <input type="checkbox" name="answer" value="${index}">
                            <span>${option || `Option ${index + 1}`}</span>
                        </label>
                    `;
                    answerOptions.appendChild(optionEl);
                });
            } else if (type === 'short_answer' || type === 'fill_in_the_blank') {
                const optionEl = document.createElement('div');
                optionEl.className = 'form-group'; // Use form-group for consistency
                optionEl.innerHTML = `
                    <label for="short-answer-input">Your Answer:</label>
                    <input type="text" id="short-answer-input" class="form-control" placeholder="Type your answer...">
                `;
                answerOptions.appendChild(optionEl);
                document.getElementById('short-answer-input')?.focus(); // Focus input
            } else {
                 throw new Error(`Unsupported question type: ${type}`);
            }
        } catch (error) {
             console.error("Error rendering answer options:", error, question);
             answerOptions.innerHTML = `<p class="text-danger">Error displaying options for this question.</p>`;
        }
    }

    // --- 4. Handle Answer Submission ---
    async function handleSubmitAnswer() {
        if (!submitAnswerBtn) return;
        stopQuestionTimer();
        submitAnswerBtn.disabled = true;

        const question = quizData[currentQuestionIndex];
        if (!question) return; // Should not happen if logic is correct

        const userAnswer = getUserAnswer(question.question_type);
        const timeSpent = (new Date() - questionStartTime) / 1000;

        // Basic validation: Check if an answer was provided for relevant types
        if (userAnswer === null || (Array.isArray(userAnswer) && userAnswer.length === 0) || (typeof userAnswer === 'string' && userAnswer.trim() === '')) {
             alert("Please select or type an answer.");
             submitAnswerBtn.disabled = false;
             startQuestionTimer(); // Resume timer if no answer selected
             return;
        }


        try {
            const response = await fetch('/api/evaluate-answer', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ question: question, user_answer: userAnswer })
            });

            if (!response.ok) {
                const errorText = await response.text(); // Get raw response text
                throw new Error(`Failed to evaluate answer. Server response: ${errorText}`);
            }

            const data = await response.json();
             if (!data.success || !data.evaluation || !data.feedback) {
                 throw new Error(data.message || 'Invalid response format from evaluation endpoint.');
            }

            const { evaluation, feedback } = data;

            if (evaluation.is_correct) score++;
            performanceHistory.push(evaluation.is_correct);

            answeredQuestions.push({ question, userAnswer, evaluation, feedback, time_spent: timeSpent });

            showFeedback(feedback, evaluation);
            highlightAnswers(question, evaluation);

            if (currentScore) currentScore.textContent = `Score: ${score}`;
            if (submitAnswerBtn) submitAnswerBtn.style.display = 'none';
            if (nextQuestionBtn) nextQuestionBtn.style.display = 'inline-block';

            updateAdaptiveDifficulty(); // Check if difficulty should change

        } catch (error) {
            console.error('Error submitting answer:', error);
            alert(`Error submitting answer: ${error.message}\nPlease try again.`);
            submitAnswerBtn.disabled = false; // Re-enable button on error
            // Optionally restart timer or handle error state differently
        }
    }

    // --- 5. Get User's Answer from DOM ---
    function getUserAnswer(type) {
        if (type === 'mcq_single') {
            const selected = document.querySelector('input[name="answer"]:checked');
            return selected ? parseInt(selected.value, 10) : null;
        }
        if (type === 'true_false') {
            const selected = document.querySelector('input[name="answer"]:checked');
            // Return boolean true/false, or null if nothing selected
            return selected ? (selected.value === 'true') : null;
        }
        if (type === 'mcq_multiple') {
            const selected = document.querySelectorAll('input[name="answer"]:checked');
            // Return array of selected indices, or empty array if none
            return Array.from(selected).map(el => parseInt(el.value, 10));
        }
        if (type === 'short_answer' || type === 'fill_in_the_blank') {
            const inputEl = document.getElementById('short-answer-input');
            // Return trimmed value, or empty string if input doesn't exist/is empty
            return inputEl ? inputEl.value.trim() : "";
        }
        return null; // Default for unknown types
    }

    // --- 6. Show Inline Feedback ---
    function showFeedback(feedback, evaluation) {
        if (!feedbackContainer || !feedbackIcon || !feedbackText || !feedbackExplanation || !feedbackHint || !feedbackHeader) return;

        feedbackContainer.style.display = 'block';
        feedbackIcon.textContent = feedback.status_icon || '?';
        feedbackText.textContent = feedback.status_text || 'Feedback';
        feedbackExplanation.textContent = feedback.explanation || 'No explanation available.';

        if (feedback.hint) {
            feedbackHint.textContent = feedback.hint;
            feedbackHint.style.display = 'block';
        } else {
            feedbackHint.style.display = 'none';
        }

        const correctnessClass = evaluation.is_correct ? 'correct' : 'incorrect';
        feedbackContainer.className = `card ${correctnessClass}`; // Apply class to container
        feedbackHeader.className = correctnessClass; // Apply class to header for text color
    }

    // --- 7. Highlight Correct/Incorrect Options ---
    function highlightAnswers(question, evaluation) {
        if (!answerOptions) return;
        const type = question.question_type;
        const optionsUI = answerOptions.querySelectorAll('.answer-option, .form-group'); // Include form-group for short answer

        // Disable all inputs within the options area
        answerOptions.querySelectorAll('input').forEach(input => input.disabled = true);
        // Add a class to indicate submission state for styling
        answerOptions.classList.add('submitted');

        try { // Add try block for safety
            if (type === 'mcq_single' || type === 'true_false') {
                // Ensure correct_answer from evaluation is used and is a string for comparison
                const correctValue = String(evaluation.correct_answer);
                optionsUI.forEach(optionEl => {
                    const input = optionEl.querySelector('input');
                    if (!input) return; // Skip if no input found
                    optionEl.classList.add('submitted'); // Add class to parent div
                    if (input.value === correctValue) {
                        optionEl.classList.add('correct');
                    } else if (input.checked) {
                        optionEl.classList.add('incorrect', 'user-selected');
                    }
                });
            } else if (type === 'mcq_multiple') {
                // Ensure correct_answer is an array and map to strings
                const correctValues = new Set((evaluation.correct_answer || []).map(String));
                optionsUI.forEach(optionEl => {
                    const input = optionEl.querySelector('input');
                     if (!input) return;
                    optionEl.classList.add('submitted');
                    if (correctValues.has(input.value)) {
                        optionEl.classList.add('correct');
                    } else if (input.checked) {
                        optionEl.classList.add('incorrect', 'user-selected');
                    }
                });
            } else if (type === 'short_answer' || type === 'fill_in_the_blank') {
                const inputEl = document.getElementById('short-answer-input');
                if (inputEl) { // Check if input exists
                    inputEl.disabled = true; // Ensure it's disabled
                    // Add classes instead of inline styles for better CSS control
                    inputEl.classList.add(evaluation.is_correct ? 'correct-input' : 'incorrect-input');
                     optionsUI.forEach(el => el.classList.add('submitted')); // Add submitted class to parent form-group
                }
            }
        } catch(error) {
             console.error("Error highlighting answers:", error, question, evaluation);
        }
    }


    // --- 8. Load Next Question ---
    function loadNextQuestion() {
        currentQuestionIndex++;
        if (answerOptions) answerOptions.classList.remove('submitted'); // Remove submitted state
        loadQuestion(currentQuestionIndex); // Will either load next or show results
    }

    // --- 9. Show Final Results ---
    function showResults() {
        stopQuestionTimer();
        if (quizContainer) quizContainer.style.display = 'none';
        if (quizResults) quizResults.style.display = 'block';
        
        const total = quizData.length;
        const percentage = total > 0 ? Math.round((score / total) * 100) : 0;
        
        // Calculate total quiz time
        if (quizStartTime) {
            const endTime = new Date();
            totalQuizTime = Math.floor((endTime - quizStartTime) / 1000); // Convert to seconds
        }
        
        // Update the improved results display
        updateResultsDisplay(score, total, percentage);
        
        saveQuizAttempt(); // Save in background
        fetchAIFeedback(); // Fetch in background
        renderResultsReview();
    }

    // --- 9a. Update Results Display ---
    function updateResultsDisplay(correctScore, totalQuestions, percentage) {
        // Update score elements
        const scorePercentage = document.getElementById('score-percentage');
        const scoreFraction = document.getElementById('score-fraction');
        const correctCount = document.getElementById('correct-count');
        const totalCount = document.getElementById('total-count');
        const gradeDisplay = document.getElementById('grade-display');
        const accuracyScore = document.getElementById('accuracy-score');
        const totalTime = document.getElementById('total-time');
        const avgTimePerQuestion = document.getElementById('avg-time-per-question');
        const completionTimestamp = document.getElementById('completion-timestamp');
        const quizDifficulty = document.getElementById('quiz-difficulty');
        const completionEmoji = document.getElementById('completion-emoji');
        const performanceMessage = document.getElementById('performance-message');
        
        if (scorePercentage) scorePercentage.textContent = `${percentage}%`;
        if (scoreFraction) scoreFraction.textContent = `${correctScore} / ${totalQuestions}`;
        if (correctCount) correctCount.textContent = correctScore;
        if (totalCount) totalCount.textContent = totalQuestions;
        if (accuracyScore) accuracyScore.textContent = `${percentage}%`;
        
        // Update timing information
        if (totalTime) {
            const minutes = Math.floor(totalQuizTime / 60);
            const seconds = totalQuizTime % 60;
            totalTime.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }
        
        if (avgTimePerQuestion) {
            const avgTime = totalQuestions > 0 ? Math.round(totalQuizTime / totalQuestions) : 0;
            avgTimePerQuestion.textContent = `${avgTime}s`;
        }
        
        if (completionTimestamp) {
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', { 
                hour: 'numeric', 
                minute: '2-digit',
                hour12: true 
            });
            completionTimestamp.textContent = `Today, ${timeString}`;
        }
        
        if (quizDifficulty) {
            quizDifficulty.textContent = currentDifficulty.charAt(0).toUpperCase() + currentDifficulty.slice(1);
        }
        
        // Calculate and display grade
        const grade = getGradeFromPercentage(percentage);
        if (gradeDisplay) {
            gradeDisplay.textContent = grade;
            gradeDisplay.className = `score-value grade grade-${grade}`;
        }
        
        // Update completion emoji based on performance
        if (completionEmoji) {
            if (percentage >= 90) completionEmoji.textContent = '🏆';
            else if (percentage >= 80) completionEmoji.textContent = '🎉';
            else if (percentage >= 70) completionEmoji.textContent = '👏';
            else if (percentage >= 60) completionEmoji.textContent = '👍';
            else if (percentage >= 50) completionEmoji.textContent = '📚';
            else completionEmoji.textContent = '💪';
        }
        
        // Update performance message
        if (performanceMessage) {
            const message = getPerformanceMessage(percentage);
            performanceMessage.innerHTML = `<p>${message}</p>`;
        }
        
        // Update score circle with animated progress
        updateScoreCircle(percentage);
    }

    // --- 9b. Get Grade from Percentage ---
    function getGradeFromPercentage(percentage) {
        if (percentage >= 90) return 'A+';
        else if (percentage >= 80) return 'A';
        else if (percentage >= 70) return 'B';
        else if (percentage >= 60) return 'C';
        else if (percentage >= 50) return 'D';
        else return 'F';
    }

    // --- 9c. Get Performance Message ---
    function getPerformanceMessage(percentage) {
        if (percentage >= 90) {
            return "Outstanding work! You've mastered this topic! 🌟";
        } else if (percentage >= 80) {
            return "Excellent performance! You're doing great! 🎯";
        } else if (percentage >= 70) {
            return "Good job! You're on the right track! 📈";
        } else if (percentage >= 60) {
            return "Not bad! Keep practicing to improve further! 💪";
        } else if (percentage >= 50) {
            return "You're making progress! Review the material and try again! 📚";
        } else {
            return "Don't give up! Every attempt helps you learn. Keep studying! 🌱";
        }
    }

    // --- 9d. Update Score Circle Animation ---
    function updateScoreCircle(percentage) {
        const scoreCircle = document.querySelector('.score-circle');
        if (!scoreCircle) return;
        
        // Calculate the angle for the conic gradient
        const angle = (percentage / 100) * 360;
        
        // Determine color based on performance
        let color = '#5b86e5'; // Default blue
        if (percentage >= 90) color = '#28a745'; // Green
        else if (percentage >= 70) color = '#17a2b8'; // Cyan
        else if (percentage >= 50) color = '#ffc107'; // Yellow
        else color = '#dc3545'; // Red
        
        // Update the conic gradient
        scoreCircle.style.background = `conic-gradient(${color} ${angle}deg, #e9ecef ${angle}deg)`;
        
        // Add animation class for smooth transition
        scoreCircle.style.transition = 'background 1s ease-in-out';
    }

    // --- 10. Save Quiz Attempt ---
    async function saveQuizAttempt() {
        // Get topic from the appropriate source
        let topic = 'General Knowledge'; // Default fallback
        
        const materialTopicEl = document.getElementById('material_topic');
        const topicEl = document.getElementById('topic');
        
        if (materialTopicEl && materialTopicEl.value && materialTopicEl.value.trim() !== '') {
            // Use material topic if it exists and is not empty
            topic = materialTopicEl.value;
        } else if (topicEl && topicEl.value) {
            // Use topic input field value
            topic = topicEl.value;
        }

        const answersPayload = answeredQuestions.map(aq => ({
            question: aq.question, userAnswer: aq.userAnswer, // Corrected variable name
            evaluation: aq.evaluation, feedback: aq.feedback,
            time_spent: Math.round(aq.time_spent || 0) // Use correct variable name and default
        }));

        try {
            console.log('Saving quiz attempt with data:', {
                topic: topic, 
                score: score, 
                total_questions: quizData.length,
                answers_count: answersPayload.length
            });
            
            const response = await fetch('/api/save-attempt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    topic: topic, score: score, total_questions: quizData.length,
                    answers: answersPayload
                })
            });
            if (!response.ok) {
                 const errorData = await response.json(); // Try to get error message
                 throw new Error(errorData.message || `HTTP error! Status: ${response.status}`);
            }
            console.log('Quiz attempt saved successfully with topic:', topic);
        } catch (error) {
            console.error('Error saving quiz attempt:', error);
            // Optionally inform user non-critically: showFlashMessage('Could not save attempt details.', 'warning');
        }
    }

    // --- 11. Fetch AI Feedback ---
     async function fetchAIFeedback() {
        if (!aiFeedbackContainer) return;
        aiFeedbackContainer.innerHTML = '<p class="loading">Generating personalized feedback...</p>';

        // Get topic from the appropriate source
        let topic = 'General Knowledge'; // Default fallback
        
        const materialTopicEl = document.getElementById('material_topic');
        const topicEl = document.getElementById('topic');
        
        if (materialTopicEl && materialTopicEl.value && materialTopicEl.value.trim() !== '') {
            // Use material topic if it exists and is not empty
            topic = materialTopicEl.value;
        } else if (topicEl && topicEl.value) {
            // Use topic input field value
            topic = topicEl.value;
        }

        const incorrect_questions = answeredQuestions
            .filter(aq => !aq.evaluation.is_correct)
            .map(aq => aq.question.question);

        try {
            const response = await fetch('/api/generate-feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    topic: topic, score: score, total_questions: quizData.length,
                    incorrect_questions: incorrect_questions
                })
            });
            if (!response.ok) {
                 const errorData = await response.json();
                 throw new Error(errorData.message || `HTTP error! Status: ${response.status}`);
            }

            const data = await response.json();
            if (data.success && data.feedback) {
                const fb = data.feedback;
                // Add checks for null/undefined feedback parts
                aiFeedbackContainer.innerHTML = `
                    <h3>Personalized Feedback</h3>
                    <p><strong>${fb.encouragement || ''}</strong></p>
                    <p><strong>Areas to Review:</strong> ${fb.weak_areas || 'N/A'}</p>
                    <p><strong>Study Tip:</strong> ${fb.study_tips || 'N/A'}</p>
                    <p><em>${fb.motivation || ''}</em></p>
                `;
            } else {
                 throw new Error(data.message || 'Invalid feedback response from server.');
            }
        } catch (error) {
            console.error('Error fetching AI feedback:', error);
            aiFeedbackContainer.innerHTML = `<p class="text-danger">Error loading AI feedback: ${error.message}</p>`;
        }
    }

    // --- 12. Render Results Review ---
    function renderResultsReview() {
        if (!resultsReviewArea) return;
        resultsReviewArea.innerHTML = '<h3>Review Your Answers</h3>'; // Reset content

        if (!answeredQuestions || answeredQuestions.length === 0) {
            resultsReviewArea.innerHTML += '<p>No answers recorded for review.</p>';
            return;
        }

        answeredQuestions.forEach((aq, index) => {
            const item = document.createElement('div');
            item.className = 'review-item';

            let answerSummary = '<p>Error displaying answer details.</p>'; // Default error message
            try { // Wrap rendering logic in try...catch
                const type = aq.question?.question_type; // Use optional chaining
                const ua = aq.userAnswer; // Correct variable name
                const ca = aq.evaluation?.correct_answer; // Use optional chaining
                const opts = aq.question?.options || [];
                const isCorrect = aq.evaluation?.is_correct;

                if (type === 'mcq_single') {
                    const userAnswerText = (ua !== null && ua >= 0 && ua < opts.length) ? opts[ua] : 'No answer';
                    const correctAnswerText = (ca !== null && ca >= 0 && ca < opts.length) ? opts[ca] : 'N/A';
                    answerSummary = `
                        <div class="review-answer ${isCorrect ? 'correct' : 'incorrect'}">Your answer: <span>${userAnswerText}</span></div>
                        ${!isCorrect ? `<div class="review-answer correct">Correct answer: <span>${correctAnswerText}</span></div>` : ''}
                    `;
                } else if (type === 'true_false') {
                    const userAnswerText = ua === true ? 'True' : ua === false ? 'False' : 'No answer';
                    const correctAnswerText = ca === true ? 'True' : ca === false ? 'False' : 'N/A';
                    answerSummary = `
                        <div class="review-answer ${isCorrect ? 'correct' : 'incorrect'}">Your answer: <span>${userAnswerText}</span></div>
                        ${!isCorrect ? `<div class="review-answer correct">Correct answer: <span>${correctAnswerText}</span></div>` : ''}
                    `;
                } else if (type === 'mcq_multiple') {
                    const userAnswersText = (Array.isArray(ua) && ua.length > 0) ? ua.map(i => (i >= 0 && i < opts.length) ? opts[i] : '?').join(', ') : 'No answer';
                    const correctAnswersText = (Array.isArray(ca) && ca.length > 0) ? ca.map(i => (i >= 0 && i < opts.length) ? opts[i] : '?').join(', ') : 'N/A';
                    answerSummary = `
                        <div class="review-answer ${isCorrect ? 'correct' : 'incorrect'}">Your answer: <span>${userAnswersText}</span></div>
                        <div class="review-answer correct">Correct answer(s): <span>${correctAnswersText}</span></div>
                    `;
                } else if (type === 'short_answer' || type === 'fill_in_the_blank') {
                    answerSummary = `
                        <div class="review-answer ${isCorrect ? 'correct' : 'incorrect'}">Your answer: <span>${ua || 'No answer'}</span></div>
                        ${!isCorrect ? `<div class="review-answer correct">Correct answer: <span>${ca || 'N/A'}</span></div>` : ''}
                    `;
                } else {
                     answerSummary = `<p>Unsupported question type for review: ${type}</p>`;
                }
            } catch(renderErr) {
                 console.error("Error rendering review summary:", renderErr, aq);
                 // Keep the default error message in answerSummary
            }

            // Ensure feedback and question objects exist before accessing properties
            const questionTextContent = aq.question?.question || '[Question Text Missing]';
            const explanationText = aq.feedback?.explanation || 'No explanation available.';

            item.innerHTML = `
                <p><strong>Q${index + 1}: ${questionTextContent}</strong></p>
                ${answerSummary}
                <p style="font-size: 0.9rem; margin-top: 0.75rem;"><em>Explanation: ${explanationText}</em></p>
            `;
            resultsReviewArea.appendChild(item);
        });
    }


    // *** NEW: Flash Message Function ***
    function showFlashMessage(message, type = 'info', duration = 4000) {
        if (!flashNotification) { console.warn("Flash notification element not found."); return; }

        clearTimeout(flashTimeout); // Clear previous timeout

        flashNotification.textContent = message;
        flashNotification.className = `flash-notification ${type}`; // Apply type class

        // Force reflow to allow transition
        void flashNotification.offsetWidth;

        flashNotification.classList.add('show');

        flashTimeout = setTimeout(() => {
            flashNotification.classList.remove('show');
            flashTimeout = null;
        }, duration);
    }
    // *** END NEW ***


    // --- 13. Update Adaptive Difficulty ---
    async function updateAdaptiveDifficulty() {
         // Send request after every answer
        try {
            const response = await fetch('/api/update-difficulty', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ performance_history: performanceHistory, current_difficulty: currentDifficulty })
            });
            // Don't throw error if request fails, just log it. Difficulty update is non-critical.
            if (!response.ok) {
                 console.warn(`Failed to update difficulty: ${response.status}`);
                 return;
            }

            const data = await response.json();
            if (data.success && data.difficulty_changed) {
                const oldDifficulty = currentDifficulty;
                currentDifficulty = data.recommended_difficulty; // Update JS state
                console.log(`Adaptive difficulty updated: ${oldDifficulty} -> ${currentDifficulty}`);

                // *** Use Flash Message ***
                showFlashMessage(`Difficulty adjusted: ${oldDifficulty.toUpperCase()} → ${currentDifficulty.toUpperCase()}`, 'info');

            } else if (data.success) {
                // Difficulty checked, no change recommended
                 console.log(`Difficulty remains: ${currentDifficulty}`);
            } else {
                 console.warn(`Update difficulty API call failed: ${data.message}`);
            }
        } catch (error) {
            console.error('Error in updateAdaptiveDifficulty fetch:', error);
            // Optionally show error flash: showFlashMessage('Could not update difficulty.', 'warning');
        }
    }


    // --- 14. Submit Question Feedback ---
    async function submitQuestionFeedback(e) {
        e.preventDefault();
        if (!feedbackComment || !feedbackFlag || !feedbackAlert || !questionFeedbackForm) return; // Safety check

        const question = quizData[currentQuestionIndex];
        const feedback_text = feedbackComment.value;
        const is_flagged = feedbackFlag.checked;

        if (!feedback_text.trim()) {
            feedbackAlert.textContent = 'Please enter feedback.';
            feedbackAlert.className = 'flash danger'; // Use flash style
            feedbackAlert.style.display = 'block';
            return;
        }

        try {
            const response = await fetch('/api/submit-feedback', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ question_text: question?.question || '[N/A]', feedback_text, is_flagged })
            });
             if (!response.ok) {
                 const errorData = await response.json();
                 throw new Error(errorData.message || `HTTP Error: ${response.status}`);
             }

            const data = await response.json();
            feedbackAlert.textContent = data.message || 'Feedback sent.';
            feedbackAlert.className = 'flash success'; // Use flash style
            feedbackAlert.style.display = 'block';
            questionFeedbackForm.reset();

            // Optionally hide the alert after a few seconds
            setTimeout(() => { if(feedbackAlert) feedbackAlert.style.display = 'none'; }, 5000);

        } catch (error) {
            console.error('Submit feedback error:', error);
            feedbackAlert.textContent = `Error: ${error.message}`;
            feedbackAlert.className = 'flash danger'; // Use flash style
            feedbackAlert.style.display = 'block';
        }
    }

    // --- 15. Question Timer ---
    function startQuestionTimer() {
        stopQuestionTimer(); // Clear existing timer
        let seconds = 0;
        if (questionTimer) questionTimer.textContent = 'Time: 0s';

        questionTimerInterval = setInterval(() => {
            seconds++;
            if (questionTimer) questionTimer.textContent = `Time: ${seconds}s`;
        }, 1000);
    }
    function stopQuestionTimer() {
        if (questionTimerInterval) {
            clearInterval(questionTimerInterval);
            questionTimerInterval = null;
        }
    }

}); // End DOMContentLoaded