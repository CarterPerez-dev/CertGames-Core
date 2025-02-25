   const updateServerProgress = useCallback(
     async (updatedAnswers, updatedScore, finished = false, singleAnswer = null) => {
       if (!userId) return;
       try {
         // If we're sending a single answer update
         if (singleAnswer) {
           await fetch(`/api/test/attempts/${userId}/${testId}/answer`, {
             method: "POST",
             headers: { "Content-Type": "application/json" },
             body: JSON.stringify({
               questionId: singleAnswer.questionId,
               userAnswerIndex: singleAnswer.userAnswerIndex,
               correctAnswerIndex: singleAnswer.correctAnswerIndex,
               score: updatedScore
             })
           });
           return;
         }
         
         // For navigation position updates (much smaller payload)
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
     [userId, testId, currentQuestionIndex]
   );
