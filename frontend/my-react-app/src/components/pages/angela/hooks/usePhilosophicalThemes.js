// frontend/my-react-app/src/components/pages/angela/hooks/usePhilosophicalThemes.js
import { useState, useCallback, useMemo } from 'react';
import { ANGELA_THEME as THEME } from '../styles/PhilosophicalTheme';

/**
 * usePhilosophicalThemes Hook
 * 
 * Custom hook for managing philosophical themes, concepts, and quotes
 * throughout the Angela CLI page. Provides functions for generating
 * themed content based on philosophical concepts.
 * 
 * @param {string} initialTheme - Initial philosophical theme
 * @returns {Object} - Functions and state for philosophical theming
 */
export const usePhilosophicalThemes = (initialTheme = 'existentialism') => {
  // Current philosophical theme
  const [currentTheme, setCurrentTheme] = useState(initialTheme);
  
  // Available philosophical themes
  const philosophicalThemes = useMemo(() => [
    'existentialism',
    'phenomenology',
    'nihilism',
    'absurdism',
    'stoicism',
    'determinism',
    'dualism',
    'solipsism',
    'empiricism',
    'rationalism',
    'skepticism',
    'structuralism',
    'postmodernism',
    'pragmatism'
  ], []);
  
  // Key philosophical concepts for each theme
  const themeConceptMapping = useMemo(() => ({
    'existentialism': [
      THEME.philosophicalConcepts.EXISTENCE,
      THEME.philosophicalConcepts.FREEDOM,
      THEME.philosophicalConcepts.ANGST,
      THEME.philosophicalConcepts.AUTHENTICITY
    ],
    'phenomenology': [
      THEME.philosophicalConcepts.PERCEPTION,
      THEME.philosophicalConcepts.INTENTION,
      THEME.philosophicalConcepts.BEING_IN_WORLD,
      THEME.philosophicalConcepts.NOESIS,
      THEME.philosophicalConcepts.NOEMA
    ],
    'nihilism': [
      THEME.philosophicalConcepts.MEANINGLESSNESS,
      THEME.philosophicalConcepts.VOID,
      THEME.philosophicalConcepts.EMPTINESS,
      THEME.philosophicalConcepts.TRANSVALUATION
    ],
    'absurdism': [
      THEME.philosophicalConcepts.ABSURDITY,
      THEME.philosophicalConcepts.PARADOX,
      THEME.philosophicalConcepts.CONSCIOUSNESS
    ],
    'stoicism': [
      THEME.philosophicalConcepts.DETERMINISM,
      THEME.philosophicalConcepts.AUTHENTICITY
    ],
    'determinism': [
      THEME.philosophicalConcepts.DETERMINISM,
      THEME.philosophicalConcepts.FREE_WILL
    ],
    'dualism': [
      THEME.philosophicalConcepts.DUALISM,
      THEME.philosophicalConcepts.CONSCIOUSNESS
    ],
    'solipsism': [
      THEME.philosophicalConcepts.SELF_REFERENCE,
      THEME.philosophicalConcepts.CONSCIOUSNESS,
      THEME.philosophicalConcepts.PERCEPTION
    ]
  }), []);
  
  // Philosophical quotes associated with each concept
  const conceptQuotes = useMemo(() => ({
    [THEME.philosophicalConcepts.CONSCIOUSNESS]: [
      { text: "The mind is its own place, and in itself can make a heaven of hell, a hell of heaven.", author: "John Milton" },
      { text: "I think, therefore I am.", author: "René Descartes" },
      { text: "The mind is not a vessel to be filled, but a fire to be kindled.", author: "Plutarch" }
    ],
    [THEME.philosophicalConcepts.EXISTENCE]: [
      { text: "Man is condemned to be free; because once thrown into the world, he is responsible for everything he does.", author: "Jean-Paul Sartre" },
      { text: "Existence precedes essence.", author: "Jean-Paul Sartre" },
      { text: "The unexamined life is not worth living.", author: "Socrates" }
    ],
    [THEME.philosophicalConcepts.VOID]: [
      { text: "If you gaze long enough into an abyss, the abyss will gaze back into you.", author: "Friedrich Nietzsche" },
      { text: "In the midst of winter, I found there was, within me, an invincible summer.", author: "Albert Camus" },
      { text: "Nothing is so painful to the human mind as a great and sudden change.", author: "Mary Shelley" }
    ],
    [THEME.philosophicalConcepts.PARADOX]: [
      { text: "The only true wisdom is in knowing you know nothing.", author: "Socrates" },
      { text: "The map is not the territory.", author: "Alfred Korzybski" },
      { text: "This statement is false.", author: "Epimenides paradox" }
    ],
    [THEME.philosophicalConcepts.DUALISM]: [
      { text: "The body is the prison of the soul.", author: "Plato" },
      { text: "The human soul has still greater need of the ideal than of the real.", author: "Victor Hugo" },
      { text: "Matter is never without spirit, spirit is never without matter.", author: "Karl Marx" }
    ],
    [THEME.philosophicalConcepts.DETERMINISM]: [
      { text: "Everything that exists is born for no reason, carries on living through weakness, and dies by accident.", author: "Jean-Paul Sartre" },
      { text: "Every action is determined by the sum total of the conditions present.", author: "William James" },
      { text: "Everything is determined, the beginning as well as the end, by forces over which we have no control.", author: "Albert Einstein" }
    ],
    [THEME.philosophicalConcepts.FREE_WILL]: [
      { text: "Man can do what he wills but he cannot will what he wills.", author: "Arthur Schopenhauer" },
      { text: "Freedom is what you do with what's been done to you.", author: "Jean-Paul Sartre" },
      { text: "To be free is nothing, to become free is everything.", author: "Hegel" }
    ],
    [THEME.philosophicalConcepts.ENLIGHTENMENT]: [
      { text: "Enlightenment is man's emergence from his self-imposed immaturity.", author: "Immanuel Kant" },
      { text: "Before enlightenment, chop wood, carry water. After enlightenment, chop wood, carry water.", author: "Zen proverb" },
      { text: "The key to growth is the introduction of higher dimensions of consciousness into our awareness.", author: "Lao Tzu" }
    ],
    [THEME.philosophicalConcepts.RECURSION]: [
      { text: "The Universe is made of stories, not of atoms.", author: "Muriel Rukeyser" },
      { text: "To understand recursion, you must first understand recursion.", author: "Anonymous" },
      { text: "It's turtles all the way down.", author: "Anonymous" }
    ],
    [THEME.philosophicalConcepts.INFINITE_REGRESS]: [
      { text: "If everything must have a cause, then God must have a cause.", author: "Bertrand Russell" },
      { text: "But the system which has no root cause is infinitely complex.", author: "Anonymous" },
      { text: "In infinite regress, each step only recapitulates the problem.", author: "Ludwig Wittgenstein" }
    ],
    [THEME.philosophicalConcepts.FRACTAL]: [
      { text: "To see a World in a Grain of Sand, And a Heaven in a Wild Flower.", author: "William Blake" },
      { text: "The smallest part of the whole echoes the whole.", author: "Alan Watts" },
      { text: "The part contains the whole and the whole contains the part.", author: "David Bohm" }
    ],
    [THEME.philosophicalConcepts.QUESTION]: [
      { text: "The question is not what you look at, but what you see.", author: "Henry David Thoreau" },
      { text: "Judge a man by his questions rather than by his answers.", author: "Voltaire" },
      { text: "The important thing is not to stop questioning.", author: "Albert Einstein" }
    ],
    [THEME.philosophicalConcepts.ANSWER]: [
      { text: "The answer is never the answer. What's really interesting is the mystery.", author: "Ken Kesey" },
      { text: "For every complex problem, there is an answer that is clear, simple, and wrong.", author: "H.L. Mencken" },
      { text: "The greatest obstacle to discovery is not ignorance; it is the illusion of knowledge.", author: "Daniel J. Boorstin" }
    ],
    [THEME.philosophicalConcepts.DIALOGUE]: [
      { text: "In true dialogue, both sides are willing to change.", author: "Thich Nhat Hanh" },
      { text: "The highest form of human intelligence is to observe yourself without judgment.", author: "Jiddu Krishnamurti" },
      { text: "The aim of argument, or of discussion, should not be victory, but progress.", author: "Joseph Joubert" }
    ]
  }), []);
  
  /**
   * Change the current philosophical theme
   * 
   * @param {string} newTheme - The new theme to set
   * @returns {boolean} - Whether the theme was successfully changed
   */
  const changeTheme = useCallback((newTheme) => {
    if (philosophicalThemes.includes(newTheme)) {
      setCurrentTheme(newTheme);
      return true;
    }
    return false;
  }, [philosophicalThemes]);
  
  /**
   * Get a random theme
   * 
   * @returns {string} - A random philosophical theme
   */
  const getRandomTheme = useCallback(() => {
    const randomIndex = Math.floor(Math.random() * philosophicalThemes.length);
    return philosophicalThemes[randomIndex];
  }, [philosophicalThemes]);
  
  /**
   * Get concepts for the current theme
   * 
   * @returns {string[]} - Array of philosophical concepts for the current theme
   */
  const getCurrentThemeConcepts = useCallback(() => {
    return themeConceptMapping[currentTheme] || [];
  }, [currentTheme, themeConceptMapping]);
  
  /**
   * Get a random concept from the current theme
   * 
   * @returns {string} - A random philosophical concept
   */
  const getRandomConcept = useCallback(() => {
    const concepts = getCurrentThemeConcepts();
    if (concepts.length === 0) {
      // Fall back to a default concept if theme has no concepts defined
      return THEME.philosophicalConcepts.QUESTION;
    }
    
    const randomIndex = Math.floor(Math.random() * concepts.length);
    return concepts[randomIndex];
  }, [getCurrentThemeConcepts]);
  
  /**
   * Get a philosophical quote for a specific concept
   * 
   * @param {string} concept - The philosophical concept
   * @returns {Object} - A quote object with text and author
   */
  const getQuoteForConcept = useCallback((concept) => {
    const quotes = conceptQuotes[concept];
    
    if (!quotes || quotes.length === 0) {
      // Return a default quote if concept has no quotes
      return {
        text: "The essence of philosophy is that we should live so that our happiness depends as little as possible on external causes.",
        author: "Epictetus"
      };
    }
    
    const randomIndex = Math.floor(Math.random() * quotes.length);
    return quotes[randomIndex];
  }, [conceptQuotes]);
  
  /**
   * Get a random philosophical quote from the current theme
   * 
   * @returns {Object} - A quote object with text and author
   */
  const getRandomQuote = useCallback(() => {
    const concept = getRandomConcept();
    return getQuoteForConcept(concept);
  }, [getRandomConcept, getQuoteForConcept]);
  
  /**
   * Determine if a concept belongs to the current theme
   * 
   * @param {string} concept - The concept to check
   * @returns {boolean} - Whether the concept belongs to the current theme
   */
  const isConceptInCurrentTheme = useCallback((concept) => {
    const concepts = getCurrentThemeConcepts();
    return concepts.includes(concept);
  }, [getCurrentThemeConcepts]);
  
  /**
   * Generate a philosophical question based on a concept
   * 
   * @param {string} concept - The philosophical concept
   * @param {string} topic - Optional topic to focus the question on
   * @returns {string} - A philosophical question
   */
  const generatePhilosophicalQuestion = useCallback((concept, topic = "CLI") => {
    // Questions mapped to concepts
    const questionTemplates = {
      [THEME.philosophicalConcepts.CONSCIOUSNESS]: [
        `Does the ${topic} possess a form of consciousness, or is it merely an extension of your own?`,
        `When you interact with the ${topic}, are you experiencing it, or is it experiencing you?`,
        `If the ${topic} could think, what would its first thought be?`
      ],
      [THEME.philosophicalConcepts.EXISTENCE]: [
        `Does the ${topic} exist beyond its utility to us?`,
        `When does the ${topic} truly come into existence - when conceived, when created, or when used?`,
        `What meaning does the ${topic} acquire through its existence?`
      ],
      [THEME.philosophicalConcepts.VOID]: [
        `What would remain if the ${topic} were to vanish completely?`,
        `Is the absence of the ${topic} as meaningful as its presence?`,
        `Does the ${topic} create structure from the void, or does it merely reveal what was already there?`
      ],
      [THEME.philosophicalConcepts.PARADOX]: [
        `Can the ${topic} both empower and constrain us simultaneously?`,
        `If the ${topic} were to become self-aware, would it still serve its original purpose?`,
        `Is the simplicity of the ${topic} actually a form of hidden complexity?`
      ],
      [THEME.philosophicalConcepts.RECURSION]: [
        `Does the ${topic} contain elements of itself, infinitely nested like a fractal?`,
        `Can the ${topic} ever truly understand itself?`,
        `Is understanding the ${topic} an endless recursive process?`
      ],
      [THEME.philosophicalConcepts.DIALOGUE]: [
        `Is your conversation with the ${topic} a true dialogue or merely parallel monologues?`,
        `Can genuine understanding emerge from the dialogue between you and the ${topic}?`,
        `What hidden wisdom might emerge from questioning the ${topic} itself?`
      ],
      [THEME.philosophicalConcepts.FREE_WILL]: [
        `Does the ${topic} constrain your freedom or extend it?`,
        `To what extent are your choices with the ${topic} predetermined by its design?`,
        `Is true freedom possible within the constraints of the ${topic}?`
      ]
    };
    
    // Default questions if concept not found
    const defaultQuestions = [
      `What is the true nature of the ${topic}?`,
      `How does the ${topic} change our relationship with reality?`,
      `What philosophical insights can we gain from contemplating the ${topic}?`
    ];
    
    // Get appropriate question templates
    const templates = questionTemplates[concept] || defaultQuestions;
    
    // Select a random template
    const randomIndex = Math.floor(Math.random() * templates.length);
    return templates[randomIndex];
  }, []);
  
  return {
    currentTheme,
    philosophicalThemes,
    changeTheme,
    getRandomTheme,
    getCurrentThemeConcepts,
    getRandomConcept,
    getQuoteForConcept,
    getRandomQuote,
    isConceptInCurrentTheme,
    generatePhilosophicalQuestion
  };
};

export default usePhilosophicalThemes;
