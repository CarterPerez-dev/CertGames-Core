   const handleOptionClick = useCallback(
     async (displayOptionIndex) => {
       // ... existing code ...
       
       // Create the new answer object
       const newAnswerObj = {
         questionId: questionObject.id,
         userAnswerIndex: actualAnswerIndex,
         correctAnswerIndex: questionObject.correctAnswerIndex
       };
       
       // Update local state
       const updatedAnswers = [...answers];
       const idx = updatedAnswers.findIndex(a => a.questionId === questionObject.id);
       if (idx >= 0) {
         updatedAnswers[idx] = newAnswerObj;
       } else {
         updatedAnswers.push(newAnswerObj);
       }
       setAnswers(updatedAnswers);
   
       // Update server with only the changed answer
       updateServerProgress(updatedAnswers, newScore, false, newAnswerObj);
       
       // ... rest of existing code ...
     },
     [/* same dependencies */]
   );
