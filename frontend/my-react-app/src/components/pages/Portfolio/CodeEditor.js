// frontend/my-react-app/src/components/pages/Portfolio/CodeEditor.js
import React, { useEffect, useRef, useState } from 'react';
import { Editor } from '@monaco-editor/react';

const CodeEditor = ({ value, language, theme, onChange, onError }) => {
  const editorRef = useRef(null);
  const [editorHeight, setEditorHeight] = useState('650px');
  const containerRef = useRef(null); // Keep containerRef if used for other styling/layout

  useEffect(() => {
    let resizeTimeout = null;

    const handleResize = () => {
      if (resizeTimeout) {
        clearTimeout(resizeTimeout);
      }

      resizeTimeout = setTimeout(() => {
        // No need to check containerRef.current here if it's not directly used for height calculation
        const viewportHeight = window.innerHeight;
        const newHeight = Math.max(500, viewportHeight * 0.6); // At least 500px, up to 60% of viewport
        setEditorHeight(`${newHeight}px`);

        // If the editor instance is available, you could also tell it to layout
        // This can sometimes be beneficial if the component wrapper doesn't always catch all scenarios
        // But often, the prop change is enough.
        // if (editorRef.current) {
        //   editorRef.current.layout();
        // }

      }, 100); // 100ms debounce
    };

    handleResize(); // Initial sizing
    window.addEventListener('resize', handleResize, { passive: true });

    return () => {
      window.removeEventListener('resize', handleResize);
      if (resizeTimeout) {
        clearTimeout(resizeTimeout);
      }
    };
  }, []); // Removed editorRef from dependency array, as it's stable


  const handleEditorDidMount = (editor, monaco) => {
    editorRef.current = editor;

    editor.updateOptions({
      lineHeight: 20,
      fontFamily: "'Fira Code', 'Consolas', monospace",
      fontLigatures: true,
      cursorSmoothCaretAnimation: "on",
    });

    if (language === 'javascript' || language === 'jsx') {
      const checkErrors = () => {
        const model = editor.getModel();
        if (!model) return; // Ensure model exists
        const markers = monaco.editor.getModelMarkers({ resource: model.uri }); // Better to use resource
        if (markers.length > 0) {
          const errorMarker = markers.sort((a, b) => b.severity - a.severity)[0];
          const errorMessage = `${errorMarker.message} (Line ${errorMarker.startLineNumber})`;
          if (onError) onError(errorMessage);
        } else {
          if (onError) onError(null);
        }
      };

      let errorCheckTimeout = null;
      editor.onDidChangeModelContent(() => {
        if (errorCheckTimeout) clearTimeout(errorCheckTimeout);
        errorCheckTimeout = setTimeout(checkErrors, 1000);
      });
      
      // Check errors on initial load if there's initial content
      if (value) {
         setTimeout(checkErrors, 1500);
      }
    }
  };

  // This useEffect to set value is fine.
  useEffect(() => {
    if (editorRef.current && editorRef.current.getValue() !== value) {
      editorRef.current.setValue(value);
    }
  }, [value]);

  return (
    <div ref={containerRef} className="portfolio-code-editor-wrapper" style={{ width: '100%' }}>
      <Editor
        // The height prop change should trigger the editor to re-layout
        height={editorHeight}
        // Ensure width is also handled, often "100%" on the Editor itself is good if its container manages width
        width="100%"
        language={language}
        theme={theme || "vs-dark"}
        value={value} // Provide initial value here
        onMount={handleEditorDidMount}
        onChange={(newValue) => onChange(newValue || '')} // Ensure newValue is not undefined
        options={{
          minimap: { enabled: true },
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          fontSize: 14,
          autoIndent: 'full',
          formatOnPaste: true,
          formatOnType: true,
          wordWrap: 'on', // 'on', 'off', 'wordWrapColumn', 'bounded'
          automaticLayout: true, // This option often helps Monaco adjust to container changes.
          scrollbar: {
            vertical: 'visible',
            horizontal: 'visible',
            useShadows: true,
            verticalHasArrows: true,
            horizontalHasArrows: true
          },
          suggest: {
            showIcons: true,
            showFunctions: true,
            showConstructors: true,
            showVariables: true,
            showClasses: true,
            showStructs: true,
            showInterfaces: true,
            showModules: true
          }
        }}
      />
    </div>
  );
};

export default CodeEditor;
