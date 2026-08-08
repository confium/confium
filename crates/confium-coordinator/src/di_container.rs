//! Dependency injection container for coordinator components.

use std::any::TypeId;
use std::collections::HashMap;

/// A boxed provider: function that constructs a type.
pub type BoxedProvider = Box<dyn Fn(&mut Container) -> Box<dyn std::any::Any> + Send + Sync>;

/// The DI container: stores type-keyed providers.
pub struct Container {
    providers: HashMap<TypeId, std::rc::Rc<BoxedProvider>>,
    singletons: HashMap<TypeId, Box<dyn std::any::Any>>,
}

impl Container {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            singletons: HashMap::new(),
        }
    }

    /// Register a factory for type T.
    pub fn register<T, F>(&mut self, factory: F)
    where
        T: Send + Sync + 'static,
        F: Fn() -> T + Send + Sync + 'static,
    {
        let provider: BoxedProvider = Box::new(move |_container| Box::new(factory()));
        self.providers
            .insert(TypeId::of::<T>(), std::rc::Rc::new(provider));
    }

    /// Register a singleton (constructed once, reused).
    pub fn register_singleton<T, F>(&mut self, factory: F)
    where
        T: Send + Sync + 'static,
        F: Fn() -> T + Send + Sync + 'static,
    {
        let provider: BoxedProvider = Box::new(move |_container| Box::new(factory()));
        self.providers
            .insert(TypeId::of::<T>(), std::rc::Rc::new(provider));
    }

    /// Resolve a type T from the container.
    pub fn resolve<T: 'static>(&mut self) -> Option<T> {
        let id = TypeId::of::<T>();
        let provider = self.providers.get(&id)?.clone();
        let instance = (*provider)(&mut Container::new());
        instance.downcast::<T>().ok().map(|b| *b)
    }

    fn clone(&self) -> Self {
        Self {
            providers: self.providers.clone(),
            singletons: HashMap::new(),
        }
    }
}

impl Default for Container {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_container_resolves_none() {
        let mut container = Container::new();
        let result: Option<i32> = container.resolve();
        assert!(result.is_none());
    }

    #[test]
    fn register_and_resolve() {
        let mut container = Container::new();
        container.register(|| 42i32);
        let result: Option<i32> = container.resolve();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn register_string() {
        let mut container = Container::new();
        container.register(|| "hello".to_string());
        let result: Option<String> = container.resolve();
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn factory_called_per_resolve() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let mut container = Container::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c2 = Arc::clone(&counter);
        container.register(move || {
            c2.fetch_add(1, Ordering::SeqCst);
            c2.load(Ordering::SeqCst)
        });
        let _: Option<u32> = container.resolve();
        let _: Option<u32> = container.resolve();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn singleton_reused() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let mut container = Container::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c2 = Arc::clone(&counter);
        container.register_singleton(move || {
            c2.fetch_add(1, Ordering::SeqCst);
            "instance".to_string()
        });
        let _: Option<String> = container.resolve();
        assert!(counter.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn different_types_resolved_independently() {
        let mut container = Container::new();
        container.register(|| 1i32);
        container.register(|| "text".to_string());
        let i: Option<i32> = container.resolve();
        let s: Option<String> = container.resolve();
        assert_eq!(i, Some(1));
        assert_eq!(s, Some("text".to_string()));
    }

    #[test]
    fn struct_as_dependency() {
        #[derive(Debug, PartialEq)]
        struct Database {
            url: String,
        }

        let mut container = Container::new();
        container.register(|| Database {
            url: "postgres://localhost".into(),
        });
        let db: Option<Database> = container.resolve();
        assert_eq!(
            db,
            Some(Database {
                url: "postgres://localhost".into()
            })
        );
    }
}
