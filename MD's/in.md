  ```javascript
  const finishTestProcess = useCallback(async () => {
    let finalScore = 0;
    answers.forEach((ans) => {
      if (ans.userAnswerIndex === ans.correctAnswerIndex) {
        finalScore++;
      }
    });
    setScore(finalScore);
  
    try {
      const res = await fetch(`/api/test/attempts/${userId}/${testId}/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          score: finalScore,
          totalQuestions
        })
      });
      const finishData = await res.json();
  
      // 1) If the backend returns newly unlocked achievements, show toasts
      if (finishData.newlyUnlocked && finishData.newlyUnlocked.length > 0) {
        finishData.newlyUnlocked.forEach((achievementId) => {
          const achievement = achievements.find(
            (a) => a.achievementId === achievementId
          );
          if (achievement) {
            const IconComp = iconMapping[achievement.achievementId] || null;
            const color = colorMapping[achievement.achievementId] || "#fff";
            showAchievementToast({
              title: achievement.title,
              description: achievement.description,
              icon: IconComp ? <IconComp /> : null,
              color
            });
          }
        });
      }
  
      // 2) If the backend returns newXP / newCoins, update Redux so the UI shows the new totals
      if (typeof finishData.newXP !== "undefined" && typeof finishData.newCoins !== "undefined") {
        dispatch(setXPAndCoins({
          xp: finishData.newXP,
          coins: finishData.newCoins
        }));
      }
  
    } catch (err) {
      console.error("Failed to finish test attempt:", err);
    }
  
    // Finally, set the UI to show the score overlay
    setIsFinished(true);
    setShowScoreOverlay(true);
    setShowReviewMode(true);
  }, [answers, userId, testId, totalQuestions, achievements, dispatch]);
  ```
