   const handleNextQuestion = useCallback(() => {
     if (currentQuestionIndex === totalQuestions - 1) {
       finishTestProcess();
       return;
     }
     const nextIndex = currentQuestionIndex + 1;
     setCurrentQuestionIndex(nextIndex);
     // Only send position update, not the full document
     updateServerProgress(answers, score, false);
   }, [/* same dependencies */]);
   
   const handlePreviousQuestion = useCallback(() => {
     if (currentQuestionIndex > 0) {
       const prevIndex = currentQuestionIndex - 1;
       setCurrentQuestionIndex(prevIndex);
       // Only send position update, not the full document
       updateServerProgress(answers, score, false);
     }
   }, [/* same dependencies */]);
