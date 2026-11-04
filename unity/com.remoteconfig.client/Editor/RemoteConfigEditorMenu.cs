using System;
using System.IO;
using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace RemoteConfig.Editor
{
    public static class RemoteConfigEditorMenu
    {
        [MenuItem("GameObject/RemoteConfig/Add Client", false, 10)]
        static void AddClient()
        {
            if (UnityEngine.Object.FindFirstObjectByType<RemoteConfigClient>() != null)
            {
                EditorUtility.DisplayDialog("RemoteConfig", "This scene already has a RemoteConfigClient.", "OK");
                return;
            }
            var go = new GameObject("RemoteConfig");
            go.AddComponent<RemoteConfigClient>();
            Undo.RegisterCreatedObjectUndo(go, "Add RemoteConfig client");
            Selection.activeGameObject = go;
        }

        [MenuItem("Tools/RemoteConfig/Create Test Scene")]
        static void CreateTestSceneMenu()
        {
            var path = EditorUtility.SaveFilePanelInProject("Save test scene", "RemoteConfigTestScene", "unity", "Where should the test scene go?");
            if (!string.IsNullOrEmpty(path)) CreateTestScene(path);
        }

        /// <summary>
        /// Builds the test scene: a camera whose colour, a cube whose spin and a title that follow
        /// the remote config, plus the on-screen panel. Also used to generate the shipped sample
        /// (run with -executeMethod RemoteConfig.Editor.RemoteConfigEditorMenu.CreateTestSceneFromCommandLine).
        /// </summary>
        public static Scene CreateTestScene(string assetPath)
        {
            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);

            var cameraGo = new GameObject("Main Camera") { tag = "MainCamera" };
            var camera = cameraGo.AddComponent<Camera>();
            camera.clearFlags = CameraClearFlags.SolidColor;
            camera.backgroundColor = new Color(0.10f, 0.14f, 0.20f);
            cameraGo.transform.position = new Vector3(0f, 1f, -6f);
            cameraGo.AddComponent<AudioListener>();

            var lightGo = new GameObject("Directional Light");
            var light = lightGo.AddComponent<Light>();
            light.type = LightType.Directional;
            lightGo.transform.rotation = Quaternion.Euler(50f, -30f, 0f);

            var cube = GameObject.CreatePrimitive(PrimitiveType.Cube);
            cube.name = "Spinner";
            cube.transform.position = new Vector3(2.5f, 0.5f, 0f);

            new GameObject("RemoteConfig").AddComponent<RemoteConfigClient>();

            var demo = new GameObject("Demo Panel").AddComponent<RemoteConfigDemoPanel>();
            var so = new SerializedObject(demo);
            so.FindProperty("targetCamera").objectReferenceValue = camera;
            so.FindProperty("spinner").objectReferenceValue = cube.transform;
            so.ApplyModifiedPropertiesWithoutUndo();

            var dir = Path.GetDirectoryName(assetPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            EditorSceneManager.SaveScene(scene, assetPath);
            AssetDatabase.Refresh();
            return scene;
        }

        /// <summary>Batch-mode entry: -executeMethod ...CreateTestSceneFromCommandLine -rcSceneOut Assets/Tmp/Scene.unity</summary>
        public static void CreateTestSceneFromCommandLine()
        {
            var args = Environment.GetCommandLineArgs();
            var path = "Assets/RemoteConfigTestScene.unity";
            for (var i = 0; i < args.Length - 1; i++)
                if (args[i] == "-rcSceneOut") path = args[i + 1];
            CreateTestScene(path);
            Debug.Log("[RemoteConfig] wrote " + path);
        }
    }
}
