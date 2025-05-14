// frontend/my-react-app/src/components/pages/Portfolio/CodeEditor.js
import React, { useEffect, useRef } from 'react';
import { Editor } from '@monaco-editor/react';

const CodeEditor = ({ value, language, theme, onChange, onError }) => {
  const editorRef = useRef(null);

  const handleEditorDidMount = (editor, monaco) => {
    editorRef.current = editor;
    
    // Set up validation for JavaScript files
    if (language === 'javascript') {
      const markers = monaco.editor.getModelMarkers({ owner: 'javascript' });
      if (markers.length > 0) {
        const errorMessage = markers[0].message;
        if (onError) onError(errorMessage);
      }
    }
  };

  useEffect(() => {
    // Make sure the editor has been mounted
    if (!editorRef.current) return;
    
    // Set the value when it changes externally
    if (editorRef.current.getValue() !== value) {
      editorRef.current.setValue(value);
    }
  }, [value]);

  return (
    <Editor
      height="500px"
      width="100%"
      language={language}
      theme={theme}
      value={value}
      onMount={handleEditorDidMount}
      onChange={(newValue) => onChange(newValue)}
      options={{
        minimap: { enabled: false },
        lineNumbers: 'on',
        scrollBeyondLastLine: false,
        fontSize: 14,
        autoIndent: 'full',
        formatOnPaste: true,
        formatOnType: true
      }}
    />
  );
};

export default CodeEditor;
