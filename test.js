   const updateServerProgress = useCallback(
     async (updatedAnswers, updatedScore, finished = false, onlyUpdateQuestion = null) => {
       if (!userId) return;
       try {
         // If we're only updating a single answer, use a targeted endpoint
         if (onlyUpdateQuestion) {
           await fetch(`/api/test/attempts/${userId}/${testId}/answer`, {
             method: "POST",
             headers: { "Content-Type": "application/json" },
             body: JSON.stringify({
               questionId: onlyUpdateQuestion.questionId,
               userAnswerIndex: onlyUpdateQuestion.userAnswerIndex,
               correctAnswerIndex: onlyUpdateQuestion.correctAnswerIndex,
               score: updatedScore
             })
           });
           return;
         }
         
         // For navigation/position updates, only send the minimal data needed
         await fetch(`/api/test/attempts/${userId}/${testId}/position`, {
           method: "POST",
           headers: { "Content-Type": "application/json" },
           body: JSON.stringify({
             currentQuestionIndex,
             finished
           })
         });
       } catch (err) {
         console.error("Failed to update test attempt on backend", err);
       }
     },
     [/* same dependencies */]
   );
