            {
                "$push": {
                    "answers": {
                        "questionId": question_id,
                        "userAnswerIndex": user_answer_index,
                        "correctAnswerIndex": correct_answer_index
                    }
                },
                "$set": {"score": data.get("score", 0)}
            }
